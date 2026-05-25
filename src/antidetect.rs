//! antidetect.rs — Anti-analysis and environment checks
//!
//! CPUID hypervisor/sandbox detection using ecx (not ebx/rbx) to avoid
//! LLVM's reserved-register constraint on rbx in x86-64 inline asm.

#![allow(dead_code, non_snake_case)]

/// Check if running inside a hypervisor via CPUID leaf 1, bit 31 of ECX.
/// LLVM reserves rbx/ebx on x86-64 — we use ecx output only and read
/// the hypervisor bit directly from there (it's in ECX.bit31, not EBX).
pub fn is_hypervisor_present() -> bool {
    let ecx_out: u32;
    unsafe {
        core::arch::asm!(
            "push rbx",         // manually save rbx (LLVM constraint)
            "cpuid",
            "pop rbx",          // restore rbx
            inout("eax") 1u32 => _,
            out("ecx") ecx_out,
            out("edx") _,
            options(nostack, nomem),
        );
    }
    // Hypervisor present bit: ECX bit 31
    (ecx_out >> 31) & 1 == 1
}

/// Check CPUID leaf 0x40000000 for known hypervisor vendor strings.
/// Returns the raw EBX/ECX/EDX chars as a 12-byte array.
pub fn hypervisor_vendor() -> [u8; 12] {
    let ebx_out: u32;
    let ecx_out: u32;
    let edx_out: u32;
    unsafe {
        core::arch::asm!(
            "push rbx",
            "cpuid",
            "mov {ebx_save}, ebx",
            "pop rbx",
            inout("eax") 0x4000_0000u32 => _,
            ebx_save = out(reg) ebx_out,
            out("ecx") ecx_out,
            out("edx") edx_out,
            options(nostack, nomem),
        );
    }
    let mut out = [0u8; 12];
    out[0..4].copy_from_slice(&ebx_out.to_le_bytes());
    out[4..8].copy_from_slice(&ecx_out.to_le_bytes());
    out[8..12].copy_from_slice(&edx_out.to_le_bytes());
    out
}

/// Detect known sandbox/VM vendor strings.
/// Returns true if any known sandbox signature is found.
pub fn is_sandbox() -> bool {
    let vendor = hypervisor_vendor();
    // Known: VMware (\x56\x4D\x77\x61...), VBox (\x56\x42\x6F\x78...),
    //        KVMKVMKVM, Microsoft Hv, XenVMMXenVMM
    const KNOWN: &[[u8; 4]] = &[
        *b"VMwa",  // VMware
        *b"VBOX",  // VirtualBox
        *b"KVMK",  // KVM
        *b"Micr",  // Microsoft Hyper-V
        *b"XenV",  // Xen
    ];
    let prefix: [u8; 4] = [vendor[0], vendor[1], vendor[2], vendor[3]];
    KNOWN.iter().any(|k| *k == prefix)
}

/// Check if the number of running processors is suspiciously low (< 2),
/// which is a common sandbox indicator.
pub fn is_low_core_count() -> bool {
    unsafe {
        let n: u32;
        core::arch::asm!(
            "push rbx",
            "cpuid",
            "pop rbx",
            inout("eax") 1u32 => _,
            out("ecx") _,
            out("edx") _,
            options(nostack, nomem),
        );
        // Logical processor count is in EBX bits 23:16 after CPUID.1
        // Re-run and capture EBX via the save trick
        let ebx_val: u32;
        core::arch::asm!(
            "push rbx",
            "cpuid",
            "mov {out}, ebx",
            "pop rbx",
            inout("eax") 1u32 => _,
            out = out(reg) ebx_val,
            out("ecx") _,
            out("edx") _,
            options(nostack, nomem),
        );
        let logical_count = (ebx_val >> 16) & 0xFF;
        logical_count < 2
    }
}

/// Run all checks. Returns true if any sandbox/VM indicator is found.
pub fn all_checks() -> bool {
    is_hypervisor_present() || is_sandbox() || is_low_core_count()
}
