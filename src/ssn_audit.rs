// ssn_audit.rs — Live ntdll SSN extractor + fallback table validator
//
// Run this as a standalone diagnostic (feature-gated so it never ships in the
// implant binary):
//
//   cargo run --bin ssn_audit --features ssn-audit
//   or call ssn_audit::run() from main.rs under #[cfg(feature = "ssn-audit")]
//
// What it does:
//   1. Resolves ntdll base from PEB.Ldr — no LoadLibrary, no GetModuleHandle API calls
//   2. Walks the ntdll EAT (Export Address Table) to find every Nt* export
//   3. For each export: reads the raw stub bytes, extracts SSN + syscall addr
//      using the same parse_stub() logic as indirect_syscall.rs
//   4. Computes djb2 hash of the function name
//   5. Cross-checks against our FALLBACK_TABLE in indirect_syscall.rs
//   6. Prints a diff report: MATCH / MISMATCH / MISSING / EXTRA
//
// Output tells you exactly which table entries need updating after a patch.
//
// Note: compile only on Windows x64 target — PEB walking is architecture-specific.

#![allow(non_snake_case, dead_code)]
#![cfg(feature = "ssn-audit")]

use crate::utils::djb2;
use crate::indirect_syscall::{
    parse_stub, get_build_number, FALLBACK_TABLE,
};

// ── PE header types needed for EAT walking ───────────────────────────────────

#[repr(C)]
struct ImageDosHeader {
    e_magic:  u16,
    _pad:     [u8; 58],
    e_lfanew: i32,
}

#[repr(C)]
struct ImageNtHeaders {
    Signature:      u32,
    FileHeader:     ImageFileHeader,
    OptionalHeader: ImageOptionalHeader64,
}

#[repr(C)]
struct ImageFileHeader {
    Machine:              u16,
    NumberOfSections:     u16,
    TimeDateStamp:        u32,
    PointerToSymbolTable: u32,
    NumberOfSymbols:      u32,
    SizeOfOptionalHeader: u16,
    Characteristics:      u16,
}

#[repr(C)]
struct ImageOptionalHeader64 {
    Magic:                       u16,
    MajorLinkerVersion:          u8,
    MinorLinkerVersion:          u8,
    SizeOfCode:                  u32,
    SizeOfInitializedData:       u32,
    SizeOfUninitializedData:     u32,
    AddressOfEntryPoint:         u32,
    BaseOfCode:                  u32,
    ImageBase:                   u64,
    SectionAlignment:            u32,
    FileAlignment:               u32,
    MajorOperatingSystemVersion: u16,
    MinorOperatingSystemVersion: u16,
    MajorImageVersion:           u16,
    MinorImageVersion:           u16,
    MajorSubsystemVersion:       u16,
    MinorSubsystemVersion:       u16,
    Win32VersionValue:           u32,
    SizeOfImage:                 u32,
    SizeOfHeaders:               u32,
    CheckSum:                    u32,
    Subsystem:                   u16,
    DllCharacteristics:          u16,
    SizeOfStackReserve:          u64,
    SizeOfStackCommit:           u64,
    SizeOfHeapReserve:           u64,
    SizeOfHeapCommit:            u64,
    LoaderFlags:                 u32,
    NumberOfRvaAndSizes:         u32,
    ExportRva:                   u32,
    ExportSize:                  u32,
    _data_dir_rest:              [u64; 30],
}

#[repr(C)]
struct ImageExportDirectory {
    Characteristics:       u32,
    TimeDateStamp:         u32,
    MajorVersion:          u16,
    MinorVersion:          u16,
    Name:                  u32,
    Base:                  u32,
    NumberOfFunctions:     u32,
    NumberOfNames:         u32,
    AddressOfFunctions:    u32,
    AddressOfNames:        u32,
    AddressOfNameOrdinals: u32,
}

// ── Result record ─────────────────────────────────────────────────────────────

#[derive(Debug)]
pub struct SsnEntry {
    pub name:         [u8; 64],
    pub name_len:     usize,
    pub hash:         u32,
    pub ssn_live:     u16,
    pub ssn_table:    Option<u16>,
    pub syscall_addr: usize,
    pub hooked:       bool,
}

impl SsnEntry {
    pub fn name_str(&self) -> &str {
        core::str::from_utf8(&self.name[..self.name_len]).unwrap_or("?")
    }
    pub fn status(&self) -> &'static str {
        match self.ssn_table {
            None                          => "MISSING ",
            Some(t) if t == self.ssn_live => "MATCH   ",
            Some(_)                       => "MISMATCH",
        }
    }
}

// ── PEB → ntdll base (no Win32 API) ──────────────────────────────────────────
//
// PEB (x64) offsets used:
//   +0x018  Ldr → PEB_LDR_DATA*
//
// PEB_LDR_DATA offsets:
//   +0x010  InLoadOrderModuleList.Flink
//
// LDR_DATA_TABLE_ENTRY offsets:
//   +0x000  InLoadOrderLinks.Flink
//   +0x018  DllBase
//   +0x038  BaseDllName (UNICODE_STRING)
//     +0x00   Length  (u16, bytes)
//     +0x08   Buffer  (*u16)

pub unsafe fn find_ntdll_base() -> Option<*const u8> {
    let peb: *const u8;
    core::arch::asm!("mov {p}, gs:[0x60]", p = out(reg) peb);
    let ldr    = *(peb.add(0x18) as *const *const u8);
    let mut e  = *(ldr.add(0x10) as *const *const u8);
    let head   = e;
    loop {
        let name_len = *(e.add(0x38) as *const u16) as usize;
        let name_buf = *(e.add(0x48) as *const *const u16);
        if name_len >= 10 {
            let sl = core::slice::from_raw_parts(name_buf, name_len / 2);
            // "ntdll" wide
            if sl.len() >= 5 &&
               sl[0] | 0x20 == b'n' as u16 &&
               sl[1] | 0x20 == b't' as u16 &&
               sl[2] | 0x20 == b'd' as u16 &&
               sl[3] | 0x20 == b'l' as u16 &&
               sl[4] | 0x20 == b'l' as u16
            {
                return Some(*(e.add(0x18) as *const *const u8));
            }
        }
        let next = *(e as *const *const u8);
        if next == head { break; }
        e = next;
    }
    None
}

// ── EAT walker ───────────────────────────────────────────────────────────────

pub unsafe fn walk_ntdll_eat(base: *const u8) -> Vec<SsnEntry> {
    let mut out = Vec::with_capacity(512);
    let build   = get_build_number();

    let dos = &*(base as *const ImageDosHeader);
    if dos.e_magic != 0x5A4D { return out; }
    let nt  = &*((base as usize + dos.e_lfanew as usize) as *const ImageNtHeaders);
    if nt.Signature != 0x0000_4550 { return out; }

    let exp_rva = nt.OptionalHeader.ExportRva as usize;
    if exp_rva == 0 { return out; }
    let exp = &*((base as usize + exp_rva) as *const ImageExportDirectory);

    let fn_rvas   = (base as usize + exp.AddressOfFunctions    as usize) as *const u32;
    let name_rvas = (base as usize + exp.AddressOfNames        as usize) as *const u32;
    let name_ords = (base as usize + exp.AddressOfNameOrdinals as usize) as *const u16;

    for i in 0..exp.NumberOfNames as usize {
        let name_ptr = (base as usize + *name_rvas.add(i) as usize) as *const u8;
        // Filter: Nt prefix only
        if *name_ptr != b'N' || *name_ptr.add(1) != b't' { continue; }

        let mut name_buf = [0u8; 64];
        let mut name_len = 0usize;
        while name_len < 63 {
            let ch = *name_ptr.add(name_len);
            if ch == 0 { break; }
            name_buf[name_len] = ch;
            name_len += 1;
        }

        let ord    = *name_ords.add(i) as usize;
        let stub   = (base as usize + *fn_rvas.add(ord) as usize) as *const u8;
        let hooked = *stub == 0xE9 || *stub == 0xFF;
        let hash   = djb2(&name_buf[..name_len]);

        let parsed = parse_stub(stub, hash);
        let ssn_live = match parsed {
            Some(ref s) => s.ssn,
            None        => continue,
        };
        let syscall_addr = parsed.map(|s| s.syscall_addr).unwrap_or(0);

        let ssn_table = FALLBACK_TABLE.iter()
            .find(|&&(b, h, _)| b == build && h == hash)
            .map(|&(_, _, ssn)| ssn);

        out.push(SsnEntry {
            name: name_buf, name_len, hash,
            ssn_live, ssn_table, syscall_addr, hooked,
        });
    }

    out.sort_by_key(|e| e.ssn_live);
    out
}

// ── Report printer ────────────────────────────────────────────────────────────

pub fn print_report(entries: &[SsnEntry]) {
    let build = unsafe { get_build_number() };
    let w = 66;

    let bar = "═".repeat(w);
    eprintln!("\n╔{}╗", bar);
    eprintln!("║  redcrab-rt SSN Audit  ·  Windows Build {:>6}{:>26}║", build, "");
    eprintln!("╠{}╣", bar);
    eprintln!("║  {:<38} {:>5}  {:>5}  {:<8}  {:<6}  ║",
        "Function", "Live", "Table", "Status", "Stub");
    eprintln!("╠{}╣", bar);

    let (mut ok, mut bad, mut miss, mut hooked_n) = (0u32, 0u32, 0u32, 0u32);

    for e in entries {
        let tbl = match e.ssn_table {
            Some(s) => format!("0x{:03X}", s),
            None    => "  ---  ".to_string(),
        };
        let hook = if e.hooked { "⚠HOOK " } else { "clean " };
        eprintln!("║  {:<38} 0x{:03X}  {}  {}  {}  ║",
            e.name_str(), e.ssn_live, tbl, e.status(), hook);
        match e.status() {
            "MATCH   " => ok   += 1,
            "MISMATCH" => bad  += 1,
            _          => miss += 1,
        }
        if e.hooked { hooked_n += 1; }
    }

    eprintln!("╠{}╣", bar);
    eprintln!("║  Nt* exports parsed : {:>4}  ·  MATCH {:>3}  ·  MISMATCH {:>3}  ·  MISSING {:>3}  ║",
        entries.len(), ok, bad, miss);
    eprintln!("║  Hooked stubs       : {:>4}  ← non-zero means EDR inline hooking active{:>4}║",
        hooked_n, "");
    eprintln!("╚{}╝\n", bar);

    if bad + miss > 0 {
        eprintln!("// ── Suggested FALLBACK_TABLE entries (build {}) ─────────────────", build);
        for e in entries {
            if e.status() != "MATCH   " {
                eprintln!("    ({}, 0x{:08x}, 0x{:02X}),  // {}",
                    build, e.hash, e.ssn_live, e.name_str());
            }
        }
        eprintln!("// ─────────────────────────────────────────────────────────────────\n");
    }
}

// ── Entry point ──────────────────────────────────────────────────────────────

pub unsafe fn run() {
    match find_ntdll_base() {
        None => eprintln!("[ssn_audit] FATAL: PEB walk failed — could not locate ntdll"),
        Some(base) => {
            eprintln!("[ssn_audit] ntdll base  : 0x{:016X}", base as usize);
            let entries = walk_ntdll_eat(base);
            if entries.is_empty() {
                eprintln!("[ssn_audit] No Nt* exports found — EAT walk failed");
            } else {
                print_report(&entries);
            }
        }
    }
}
