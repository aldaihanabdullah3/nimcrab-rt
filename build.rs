// build.rs — Link flags + automated djb2 hash extraction from live ntdll.dll
//
// HOW THE HASH PIPELINE WORKS:
//
//   1. This script builds tools/hashgen (a tiny standalone binary) via
//      `cargo build --manifest-path tools/hashgen/Cargo.toml --release`.
//      hashgen has zero external dependencies and compiles in ~1 second.
//
//   2. hashgen is invoked with the ntdll.dll path (auto-detected or
//      overridden via NTDLL_PATH env var). It parses the live EAT,
//      computes djb2 for every symbol in its SYMBOLS list, and prints
//      KEY=VALUE lines to stdout.
//
//   3. This script reads those KEY=VALUE pairs and emits:
//        cargo:rustc-env=HASH_<SYMBOL>=0xDEADBEEF
//      for each one. The source files then read these via the hash_of!()
//      macro (defined in src/hashes.rs) which calls env!() at compile time.
//
//   4. cargo:rerun-if-changed=ntdll.dll ensures the build reruns
//      automatically after a Windows Update patches ntdll.
//
// OVERRIDES:
//   NTDLL_PATH=C:\path\to\custom\ntdll.dll
//     Point at a specific ntdll (e.g. from a target-OS VM snapshot).
//
//   SKIP_HASHGEN=1
//     Skip hash generation entirely (use when cross-compiling on Linux
//     without a Windows ntdll available). The hash_of!() macro will
//     use fallback values compiled into src/hashes.rs in this case.

use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    // ── 1. Linker flags (unchanged from original) ────────────────────────────
    println!("cargo:rustc-link-arg=/NODEFAULTLIB");
    println!("cargo:rustc-link-arg=/ENTRY:main");
    println!("cargo:rustc-link-arg=/SUBSYSTEM:CONSOLE");
    println!("cargo:rustc-link-arg=/MERGE:.rdata=.text");
    println!("cargo:rustc-link-arg=/MERGE:.pdata=.text");
    println!("cargo:rustc-link-arg=/FIXED");

    // ── 2. Skip if SKIP_HASHGEN=1 (cross-compile mode) ───────────────────────
    if std::env::var("SKIP_HASHGEN").as_deref() == Ok("1") {
        eprintln!("[build.rs] SKIP_HASHGEN=1: using fallback hash values from src/hashes.rs");
        return;
    }

    // ── 3. Locate ntdll.dll ────────────────────────────────────────────────────
    let ntdll_path: PathBuf = if let Ok(p) = std::env::var("NTDLL_PATH") {
        PathBuf::from(p)
    } else {
        // Auto-detect: prefer SysNative (runs from 32-bit build tool context),
        // fall back to System32, then SysWOW64.
        let candidates = [
            r"C:\Windows\System32\ntdll.dll",
            r"C:\Windows\SysNative\ntdll.dll",
            r"C:\Windows\SysWOW64\ntdll.dll",
        ];
        candidates.iter()
            .map(PathBuf::from)
            .find(|p| p.exists())
            .unwrap_or_else(|| PathBuf::from(r"C:\Windows\System32\ntdll.dll"))
    };

    // Tell cargo to rerun this build script if ntdll itself changes
    // (covers the case where Windows Update patches it between builds).
    println!("cargo:rerun-if-changed={}", ntdll_path.display());
    println!("cargo:rerun-if-changed=tools/hashgen/src/main.rs");
    println!("cargo:rerun-if-changed=build.rs");

    eprintln!("[build.rs] ntdll.dll path: {}", ntdll_path.display());

    // ── 4. Build hashgen if not already built ────────────────────────────────
    let manifest = Path::new("tools/hashgen/Cargo.toml");
    let hashgen_build = Command::new("cargo")
        .args([
            "build",
            "--manifest-path", manifest.to_str().unwrap(),
            "--release",
            "--quiet",
        ])
        .output();

    match hashgen_build {
        Err(e) => {
            eprintln!("[build.rs] warning: could not build hashgen: {}", e);
            eprintln!("[build.rs] falling back to compile-time constants in src/hashes.rs");
            return;
        }
        Ok(out) if !out.status.success() => {
            eprintln!("[build.rs] warning: hashgen build failed:\n{}",
                String::from_utf8_lossy(&out.stderr));
            eprintln!("[build.rs] falling back to compile-time constants in src/hashes.rs");
            return;
        }
        Ok(_) => eprintln!("[build.rs] hashgen built OK"),
    }

    // Locate the compiled binary (target/release/ relative to hashgen crate)
    let hashgen_bin = Path::new("tools/hashgen/target/release/hashgen.exe");
    if !hashgen_bin.exists() {
        eprintln!("[build.rs] warning: hashgen.exe not found at {:?}, falling back", hashgen_bin);
        return;
    }

    // ── 5. Run hashgen against live ntdll ───────────────────────────────────
    let run_out = Command::new(hashgen_bin)
        .arg(ntdll_path.to_str().unwrap())
        .output();

    let run_out = match run_out {
        Err(e) => {
            eprintln!("[build.rs] warning: hashgen execution failed: {}", e);
            return;
        }
        Ok(o) => o,
    };

    // Print hashgen's stderr so it appears in `cargo build -vv` output
    if !run_out.stderr.is_empty() {
        eprintln!("{}", String::from_utf8_lossy(&run_out.stderr));
    }

    if !run_out.status.success() {
        let code = run_out.status.code().unwrap_or(-1);
        if code == 2 {
            // Exit code 2 = missing symbols — this is a hard build error
            panic!("[build.rs] hashgen: one or more NT symbols not found in ntdll EAT. \
                    Inspect hashgen stderr above. Cannot proceed.");
        }
        eprintln!("[build.rs] warning: hashgen exited with code {}, falling back", code);
        return;
    }

    // ── 6. Parse KEY=VALUE output and emit cargo:rustc-env ──────────────────
    let stdout = String::from_utf8_lossy(&run_out.stdout);
    let mut count = 0usize;

    for line in stdout.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') { continue; }
        if let Some((key, val)) = line.split_once('=') {
            if key.starts_with("HASH_") {
                println!("cargo:rustc-env={}={}", key.trim(), val.trim());
                count += 1;
            }
        }
    }

    eprintln!("[build.rs] emitted {} HASH_* environment variables for compile-time use", count);
    println!("cargo:rustc-env=HASHGEN_LIVE=1"); // signals hashes.rs that live values were used
}
