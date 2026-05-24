# RedCrab — Windows x64 Red Team Implant Framework

> ⚠️ **Authorized use only.** This is offensive security tooling built for scoped red team engagements with explicit written authorization. Unauthorized use is illegal under CFAA, India IT Act 2000, and equivalent laws.

---

## Architecture Overview

```
src/
├── main.rs          Entry point — init order + glue
├── defs.rs          NT type definitions (HANDLE, PVOID, CONTEXT, etc.)
├── utils.rs         djb2 hash, wide string helpers
├── syscall.rs       Hell's Gate + Halo's Gate direct syscall engine
├── loader.rs        Reflective PE mapper (no disk, no LoadLibrary)
├── stomp.rs         Module stomping + PEB name spoofing
├── spoof.rs         Synthetic call stack frame injection
├── sleep.rs         Ekko-style RC4-encrypted sleep mask
├── etw_patch.rs     ETW-Ti + AMSI blind (6 patch sites)
└── unhook.rs        Full ntdll .text re-read from clean disk copy
```

---

## Module Details

### `syscall.rs` — Direct Syscall Engine
- **Hell's Gate**: walks ntdll export table, reads SSN from `mov eax, <ssn>` prologue
- **Halo's Gate**: if prologue is hooked (jmp), walks ±1 neighboring syscall stubs to infer SSN
- **Trampoline**: naked function that sets up `syscall` instruction with correct calling convention
- Resolves: `NtProtectVirtualMemory`, `NtAllocateVirtualMemory`, `NtFreeVirtualMemory`, `NtFlushInstructionCache`, `NtOpenFile`, `NtCreateSection`, `NtMapViewOfSection`, `NtUnmapViewOfSection`, `NtClose`

### `unhook.rs` — ntdll .text Re-read
- Opens `ntdll.dll` from `\??\C:\Windows\System32\` via `NtOpenFile` direct syscall
- Maps a clean `SEC_IMAGE` view via `NtCreateSection + NtMapViewOfSection`
- **Page-granular diff**: compares hooked vs clean `.text` 4KB at a time, only overwrites differing pages → minimal write footprint
- Flushes instruction cache on patched region via `NtFlushInstructionCache`
- Removes clean mapping — no trace left
- Removes ALL EDR inline hooks (CrowdStrike, SentinelOne, Defender ATP, Cylance) in one pass

### `etw_patch.rs` — ETW + AMSI Blind

| Function | Patch Bytes | Effect |
|---|---|---|
| `EtwEventWrite` | `C3` | All usermode ETW events silenced |
| `EtwEventWriteFull` | `C3` | Secondary ETW path dead |
| `EtwNotificationRegister` | `31 C0 C3` | New providers can't register |
| `AmsiScanBuffer` | `31 C0 C3` | PowerShell/CLR/JScript scans return CLEAN |
| `AmsiScanString` | `31 C0 C3` | String AMSI path blind |
| `AmsiInitialize` | `31 C0 FF C8 C3` | AMSI context never initializes |

All patches via `NtProtectVirtualMemory` direct syscall. All reversible — originals saved in `PatchSite` structs.

### `sleep.rs` — Encrypted Sleep Mask
- Ekko-style timer queue chain using `NtContinue` as callback
- **Chain**: `VirtualProtect(RX→RW)` → `SystemFunction032(RC4 encrypt)` → `SetEvent(sleep)` → *[sleep window]* → `SystemFunction032(RC4 decrypt)` → `VirtualProtect(RW→RX)` → `SetEvent(wake)`
- Main thread sleeps on `WaitForSingleObject` — call stack looks like benign timer wait
- Memory is `RW` + fully RC4-encrypted during the entire sleep window
- Two separate events fix the original Ekko double-wait bug
- `NtContinue(ctx_thread)` called on main thread (not timer thread) for clean resume

### `loader.rs` — Reflective PE Mapper
- Maps a PE (exe or dll) fully from a byte slice — no `LoadLibrary`, no disk touch
- Handles: MZ/PE header validation, section mapping, base relocations (delta patching), import table resolution via PEB walk + djb2 hash, TLS callbacks
- Returns mapped base + entry point

### `stomp.rs` — Module Stomping
- Loads a legitimate decoy DLL (`xpsservices.dll` by default) into memory
- Copies payload PE into the decoy's `.text` section → payload masquerades as legit module
- Wipes PE headers of the stomped region
- Patches PEB `LDR_DATA_TABLE_ENTRY` to show decoy module name/path
- Forensic analysis sees `xpsservices.dll` in memory, not the payload

### `spoof.rs` — Call Stack Spoofing
- Gadget-based synthetic frame injection
- Locates `ret` gadgets inside Windows system DLLs (`kernel32`, `ntdll`, `user32`)
- Builds a fake call stack of legitimate-looking frames before executing payload
- Thread call stack appears to originate from `WaitForSingleObjectEx` → `BaseThreadInitThunk` chain

### `defs.rs` — NT Type Definitions
- `CONTEXT` (16-byte aligned, 1232 bytes), `UNICODE_STRING`, `OBJECT_ATTRIBUTES`, `IO_STATUS_BLOCK`, `IMAGE_*` headers, `LDR_DATA_TABLE_ENTRY`, `PEB`, `TEB`, all `NTSTATUS` codes, page protection constants

### `utils.rs` — Helpers
- `djb2(bytes)` — hash function for PEB export resolution (no strings in binary)
- `djb2_u16(wide)` — same for wide strings
- Wide string helpers

---

## Build

```bash
# Requires nightly Rust
rustup override set nightly
cargo build --release --target x86_64-pc-windows-msvc
```

Output: `target/x86_64-pc-windows-msvc/release/redcrab.exe`

---

## Initialization Order

```
0. unhook_ntdll()        ← wipe all EDR hooks from ntdll .text FIRST
1. apply_all_blinds()    ← kill ETW-Ti + AMSI (6 sites)
2. map_pe(PAYLOAD)       ← reflectively load beacon in memory
3. stomp(decoy, ...)     ← move payload into legit module .text
4. sleep_mask loop       ← run with RC4-encrypted sleep + spoofed call stack
```

---

## Defense Coverage Matrix

| Defense Layer | Detection Vector | Technique Used |
|---|---|---|
| EDR API hooks | Inline hooks in ntdll | `unhook.rs` page-granular .text overwrite |
| ETW Threat Intelligence | `EtwEventWrite` telemetry | `etw_patch.rs` ret-sled |
| AMSI | `AmsiScanBuffer` | `etw_patch.rs` xor eax,eax; ret |
| Memory scanning | RX pages with payload bytes | `sleep.rs` RC4 encrypt + RW during sleep |
| Call stack inspection | Suspicious thread frames | `spoof.rs` synthetic legitimate frames |
| Module forensics | Unknown DLL in memory | `stomp.rs` decoy module identity |
| Static signature | Binary patterns | `loader.rs` in-memory only, no disk |
| Import analysis | Suspicious imports | PEB walk + djb2 hash, no static imports |

---

## Per-Build Hardening Checklist

- [ ] Replace `SLEEP_KEY` in `main.rs` with 32 random bytes
- [ ] Replace `PAYLOAD` with your actual shellcode/PE
- [ ] Change `DECOY_DLL` to a different legit module per engagement
- [ ] Recompile — `opt-level=z` + `strip=true` minimizes binary footprint
