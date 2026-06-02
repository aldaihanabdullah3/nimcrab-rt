# selfdestruct.nim — In-memory wipe, file deletion, process termination

import winim

proc zeroOwnHeaders() =
  # unsafe — find PEB.ImageBaseAddress and zero first 4 KB
  var peb: uint
  {.emit: """__asm__ volatile ("mov %0, qword ptr gs:[0x60]" : "=r"(`peb`));""".}
  let imageBase = cast[ptr byte](cast[ptr uint](peb + 0x10)[])
  zeroMem(imageBase, 4096)

proc ownPathWide(): seq[uint16] =
  # unsafe
  var buf = newSeq[uint16](512)
  let len = GetModuleFileNameW(nil, cast[LPWSTR](addr buf[0]), 512)
  buf.setLen(int(len) + 1)  # keep null terminator
  buf

proc wipe*() =
  # unsafe
  zeroOwnHeaders()
  let path = ownPathWide()

  let hFile = CreateFileW(
    cast[LPCWSTR](addr path[0]),
    DELETE,
    FILE_SHARE_DELETE,
    nil,
    OPEN_EXISTING,
    0x04000000'u32,  # FILE_FLAG_DELETE_ON_CLOSE
    nil)

  if hFile != INVALID_HANDLE_VALUE:
    var zeros = newSeq[byte](4096)
    var written: DWORD = 0
    discard WriteFile(hFile, addr zeros[0], DWORD(zeros.len), addr written, nil)
    discard CloseHandle(hFile)
  else:
    discard DeleteFileW(cast[LPCWSTR](addr path[0]))

proc fullDestruct*() {.noReturn.} =
  # unsafe
  wipe()
  discard TerminateProcess(GetCurrentProcess(), 0)
  while true: discard  # satisfy {.noReturn.}

proc ctrlHandler(ctrlType: DWORD): BOOL {.stdcall.} =
  fullDestruct()

proc registerCtrlHandler*() =
  # unsafe
  discard SetConsoleCtrlHandler(ctrlHandler, TRUE)
