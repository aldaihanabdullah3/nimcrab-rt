// defs.rs — NT type definitions
#![allow(non_snake_case, non_camel_case_types, dead_code)]

use core::ffi::c_void;

pub type HANDLE      = *mut c_void;
pub type PVOID       = *mut c_void;
pub type SIZE_T      = usize;
pub type ULONG       = u32;
pub type NTSTATUS    = i32;
pub type LARGE_INTEGER = i64;

pub const PAGE_READONLY:     u32 = 0x02;
pub const PAGE_READWRITE:    u32 = 0x04;
pub const PAGE_EXECUTE_READ: u32 = 0x20;
pub const IMAGE_DOS_SIGNATURE: u16 = 0x5A4D;

pub const fn NT_SUCCESS(s: NTSTATUS) -> bool { s >= 0 }

#[repr(C)]
pub struct UNICODE_STRING {
    pub Length:        u16,
    pub MaximumLength: u16,
    pub Buffer:        *mut u16,
}

#[repr(C)]
pub struct OBJECT_ATTRIBUTES {
    pub Length:                   u32,
    pub RootDirectory:            HANDLE,
    pub ObjectName:               *mut UNICODE_STRING,
    pub Attributes:               u32,
    pub SecurityDescriptor:       *mut c_void,
    pub SecurityQualityOfService: *mut c_void,
}

#[repr(C)]
pub struct IO_STATUS_BLOCK {
    pub Status:      i32,
    pub Information: usize,
}

#[repr(C)]
pub struct IMAGE_FILE_HEADER {
    pub Machine:              u16,
    pub NumberOfSections:     u16,
    pub TimeDateStamp:        u32,
    pub PointerToSymbolTable: u32,
    pub NumberOfSymbols:      u32,
    pub SizeOfOptionalHeader: u16,
    pub Characteristics:      u16,
}

#[repr(C)]
pub struct IMAGE_SECTION_HEADER {
    pub Name:                 [u8; 8],
    pub VirtualSize:          u32,
    pub VirtualAddress:       u32,
    pub SizeOfRawData:        u32,
    pub PointerToRawData:     u32,
    pub PointerToRelocations: u32,
    pub PointerToLinenumbers: u32,
    pub NumberOfRelocations:  u16,
    pub NumberOfLinenumbers:  u16,
    pub Characteristics:      u32,
}

#[repr(align(16))]
#[derive(Clone)]
pub struct CONTEXT(pub [u8; 1232]);

impl CONTEXT {
    pub fn new() -> Self { CONTEXT([0u8; 1232]) }
}

#[repr(C)]
pub struct USTRING {
    pub Length:        u32,
    pub MaximumLength: u32,
    pub Buffer:        *mut c_void,
}

pub const WT_EXECUTEINTIMERTHREAD: u32 = 0x00000020;
pub const PAGE_EXECUTE_READWRITE: u32  = 0x40;
