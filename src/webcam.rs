//! webcam.rs — Single JPEG frame capture via Media Foundation
//!
//! Targets windows-rs 0.58+ API shape:
//!   MFCreateSourceReaderFromMediaSource  — returns IMFSourceReader (not out-param)
//!   IMFMediaBuffer::ConvertToContiguousBuffer — returns IMFMediaBuffer (not out-param)

#![allow(dead_code, non_snake_case)]

use windows::{
    core::*,
    Win32::Media::MediaFoundation::*,
    Win32::System::Com::*,
};

/// Capture a single JPEG frame from the first available webcam.
/// Returns raw JPEG bytes on success.
pub fn capture_frame() -> Option<Vec<u8>> {
    unsafe { capture_frame_inner().ok() }
}

unsafe fn capture_frame_inner() -> windows::core::Result<Vec<u8>> {
    // Initialize MF and COM
    CoInitializeEx(None, COINIT_APARTMENTTHREADED).ok()?;
    MFStartup(MF_VERSION, MFSTARTUP_NOSOCKET)?;

    // Enumerate video capture devices
    let mut attrs: Option<IMFAttributes> = None;
    MFCreateAttributes(&mut attrs, 1)?;
    let attrs = attrs.unwrap();
    attrs.SetGUID(
        &MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE,
        &MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE_VIDCAP_GUID,
    )?;

    let mut devices: *mut Option<IMFActivate> = core::ptr::null_mut();
    let mut count: u32 = 0;
    MFEnumDeviceSources(&attrs, &mut devices, &mut count)?;

    if count == 0 {
        return Err(windows::core::Error::from_win32());
    }

    // Use first device
    let device_slice = core::slice::from_raw_parts(devices, count as usize);
    let activate = device_slice[0].as_ref().ok_or_else(windows::core::Error::from_win32)?;
    let source: IMFMediaSource = activate.ActivateObject()?;

    // windows-rs 0.58: MFCreateSourceReaderFromMediaSource returns the reader directly
    let reader: IMFSourceReader = MFCreateSourceReaderFromMediaSource(&source, None)?;

    // Configure output format to NV12 (we'll convert to JPEG)
    let mut media_type: Option<IMFMediaType> = None;
    MFCreateMediaType(&mut media_type)?;
    let mt = media_type.unwrap();
    mt.SetGUID(&MF_MT_MAJOR_TYPE, &MFMediaType_Video)?;
    mt.SetGUID(&MF_MT_SUBTYPE, &MFVideoFormat_NV12)?;
    reader.SetCurrentMediaType(
        MF_SOURCE_READER_FIRST_VIDEO_STREAM.0 as u32,
        None,
        &mt,
    )?;

    // Read one sample
    let mut flags: u32 = 0;
    let mut timestamp: i64 = 0;
    let mut sample: Option<IMFSample> = None;
    reader.ReadSample(
        MF_SOURCE_READER_FIRST_VIDEO_STREAM.0 as u32,
        0,
        None,
        Some(&mut flags),
        Some(&mut timestamp),
        Some(&mut sample),
    )?;

    let sample = sample.ok_or_else(windows::core::Error::from_win32)?;

    // windows-rs 0.58: ConvertToContiguousBuffer returns IMFMediaBuffer directly
    let buffer: IMFMediaBuffer = sample.ConvertToContiguousBuffer()?;

    let mut data_ptr: *mut u8 = core::ptr::null_mut();
    let mut max_len: u32 = 0;
    let mut cur_len: u32 = 0;
    buffer.Lock(&mut data_ptr, Some(&mut max_len), Some(&mut cur_len))?;

    let frame_bytes = core::slice::from_raw_parts(data_ptr, cur_len as usize).to_vec();
    buffer.Unlock()?;

    MFShutdown()?;

    Ok(frame_bytes)
}
