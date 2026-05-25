//! antidetect.rs — Anti-analysis and environment checks
//!
//! CPUID blocks use push/pop rbx to avoid LLVM's reserved-register error.
#![allow(dead_code, non_snake_case)]

pub fn is_hypervisor_present() -> bool {
    let ecx_out: u32;
    unsafe {
        core::arch::asm!(
            "push rbx",
            "cpuid",
            "pop rbx",
            inout("eax") 1u32 => _,
            out("ecx") ecx_out,
            out("edx") _,
            options(nostack, nomem),
        );
    }
    (ecx_out >> 31) & 1 == 1
}

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

pub fn is_sandbox() -> bool {
    let vendor = hypervisor_vendor();
    const KNOWN: &[[u8; 4]] = &[
        *b"VMwa", *b"VBOX", *b"KVMK", *b"Micr", *b"XenV",
    ];
    let prefix: [u8; 4] = [vendor[0], vendor[1], vendor[2], vendor[3]];
    KNOWN.iter().any(|k| *k == prefix)
}

pub fn is_low_core_count() -> bool {
    let ebx_val: u32;
    unsafe {
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
    }
    let logical_count = (ebx_val >> 16) & 0xFF;
    logical_count < 2
}

pub fn all_checks() -> bool {
    is_hypervisor_present() || is_sandbox() || is_low_core_count()
}
