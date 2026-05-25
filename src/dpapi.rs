//! dpapi.rs — Credential blob encryption/decryption via CryptProtectData / CryptUnprotectData
//!
//! Uses winapi::um::wincrypt for CRYPTOAPI_BLOB — the type lives in wincrypt, NOT dpapi.

#![allow(dead_code, non_snake_case)]

use winapi::um::wincrypt::{
    CryptProtectData, CryptUnprotectData,
    DATA_BLOB,                         // CRYPTOAPI_BLOB typedef lives here
    CRYPTPROTECT_LOCAL_MACHINE,
};
use winapi::shared::minwindef::DWORD;

/// Encrypt `plaintext` bytes using DPAPI (current user scope).
/// Returns the encrypted blob on success.
pub unsafe fn dpapi_encrypt(plaintext: &[u8]) -> Option<Vec<u8>> {
    let mut in_blob = DATA_BLOB {
        cbData: plaintext.len() as DWORD,
        pbData: plaintext.as_ptr() as *mut u8,
    };
    let mut out_blob = DATA_BLOB {
        cbData: 0,
        pbData: core::ptr::null_mut(),
    };

    let ok = CryptProtectData(
        &mut in_blob,
        core::ptr::null(),
        core::ptr::null_mut(),
        core::ptr::null_mut(),
        core::ptr::null_mut(),
        0,
        &mut out_blob,
    );
    if ok == 0 { return None; }

    let slice = core::slice::from_raw_parts(out_blob.pbData, out_blob.cbData as usize);
    let result = slice.to_vec();
    winapi::um::winbase::LocalFree(out_blob.pbData as *mut _);
    Some(result)
}

/// Decrypt a DPAPI blob produced by `dpapi_encrypt`.
/// Returns the plaintext bytes on success.
pub unsafe fn dpapi_decrypt(ciphertext: &[u8]) -> Option<Vec<u8>> {
    let mut in_blob = DATA_BLOB {
        cbData: ciphertext.len() as DWORD,
        pbData: ciphertext.as_ptr() as *mut u8,
    };
    let mut out_blob = DATA_BLOB {
        cbData: 0,
        pbData: core::ptr::null_mut(),
    };

    let ok = CryptUnprotectData(
        &mut in_blob,
        core::ptr::null_mut(),
        core::ptr::null_mut(),
        core::ptr::null_mut(),
        core::ptr::null_mut(),
        0,
        &mut out_blob,
    );
    if ok == 0 { return None; }

    let slice = core::slice::from_raw_parts(out_blob.pbData, out_blob.cbData as usize);
    let result = slice.to_vec();
    winapi::um::winbase::LocalFree(out_blob.pbData as *mut _);
    Some(result)
}
