//! webcam.rs — Single frame capture via Media Foundation (windows-rs 0.58+)
#![allow(dead_code, non_snake_case)]

use windows::{
    core::*,
    Win32::Media::MediaFoundation::*,
    Win32::System::Com::*,
};

// MF_VERSION value used by MFStartup — defined as 0x00020070 in mfapi.h
// Some windows-rs builds don't re-export it; define it ourselves.
const MF_VERSION_VAL: u32 = 0x0002_0070;
// MFSTARTUP_NOSOCKET = 0x1
const MFSTARTUP_NOSOCKET_VAL: u32 = 0x1;

pub fn capture_frame() -> Option<Vec<u8>> {
    unsafe { capture_frame_inner().ok() }
}

unsafe fn capture_frame_inner() -> windows::core::Result<Vec<u8>> {
    CoInitializeEx(None, COINIT_APARTMENTTHREADED).ok()?;
    MFStartup(MF_VERSION_VAL, MFSTARTUP_NOSOCKET_VAL)?;

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

    let device_slice = core::slice::from_raw_parts(devices, count as usize);
    let activate = device_slice[0].as_ref().ok_or_else(windows::core::Error::from_win32)?;
    let source: IMFMediaSource = activate.ActivateObject()?;

    // windows-rs 0.58: returns reader directly (not out-param)
    let reader: IMFSourceReader = MFCreateSourceReaderFromMediaSource(&source, None)?;

    let mut mt_opt: Option<IMFMediaType> = None;
    MFCreateMediaType(&mut mt_opt)?;
    let mt = mt_opt.unwrap();
    mt.SetGUID(&MF_MT_MAJOR_TYPE, &MFMediaType_Video)?;
    mt.SetGUID(&MF_MT_SUBTYPE, &MFVideoFormat_NV12)?;
    reader.SetCurrentMediaType(
        MF_SOURCE_READER_FIRST_VIDEO_STREAM.0 as u32,
        None,
        &mt,
    )?;

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

    // windows-rs 0.58: returns buffer directly
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
