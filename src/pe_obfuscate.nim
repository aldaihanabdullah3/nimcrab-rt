# pe_obfuscate.nim — Compile-time string XOR + import hash obfuscation

import winim

proc xorBytes*(s: string, key: byte): array[64, byte] =
  for i in 0 ..< min(s.len, 64):
    result[i] = byte(s[i]) xor key

proc decodeXor*(enc: seq[byte], key: byte): seq[byte] =
  result = newSeq[byte](enc.len)
  for i, b in enc:
    result[i] = b xor key
  # Trim at first null
  var pos = result.len
  for i, b in result:
    if b == 0:
      pos = i + 1
      break
  result.setLen(pos)

proc hashStr*(s: string): uint32 =
  var h: uint32 = 5381
  for c in s:
    h = h * 33 + uint32(byte(c))
  h

proc resolveByHash*(moduleBase: pointer, targetHash: uint32): pointer =
  # unsafe — EAT walk
  let bp  = cast[uint](moduleBase)
  let dos = cast[ptr IMAGE_DOS_HEADER](bp)
  if dos[].e_magic != 0x5A4D'u16: return nil
  let nt      = cast[ptr IMAGE_NT_HEADERS64](bp + uint(dos[].e_lfanew))
  let expRva  = uint(nt[].OptionalHeader.DataDirectory[0].VirtualAddress)
  if expRva == 0: return nil
  let exp     = cast[ptr IMAGE_EXPORT_DIRECTORY](bp + expRva)
  let names   = cast[ptr uint32](bp + uint(exp[].AddressOfNames))
  let funcs   = cast[ptr uint32](bp + uint(exp[].AddressOfFunctions))
  let ords    = cast[ptr uint16](bp + uint(exp[].AddressOfNameOrdinals))
  let count   = int(exp[].NumberOfNames)
  for i in 0 ..< count:
    let nameRva = uint(cast[ptr uint32](cast[uint](names) + uint(i) * 4)[])
    let nptr    = cast[ptr byte](bp + nameRva)
    var length  = 0
    while cast[ptr byte](cast[uint](nptr) + uint(length))[] != 0: inc length
    var h: uint32 = 5381
    for j in 0 ..< length:
      h = h * 33 + uint32(cast[ptr byte](cast[uint](nptr) + uint(j))[])
    if h == targetHash:
      let ord    = uint(cast[ptr uint16](cast[uint](ords) + uint(i) * 2)[])
      let fnRva  = uint(cast[ptr uint32](cast[uint](funcs) + ord * 4)[])
      return cast[pointer](bp + fnRva)
  nil

proc xorPayloadInplace*(buf: var seq[byte], key: seq[byte]) =
  if key.len == 0: return
  for i in 0 ..< buf.len:
    buf[i] = buf[i] xor key[i mod key.len]

proc secureZero*(buf: var seq[byte]) =
  for i in 0 ..< buf.len:
    cast[ptr byte](addr buf[i])[] = 0  # volatile-style write

proc widePtr*(s: string): seq[uint16] =
  result = newSeq[uint16](s.len + 1)
  for i, c in s:
    result[i] = uint16(c)
  result[s.len] = 0
