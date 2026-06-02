# utils.nim — djb2 hash + wide string helpers
# Translated from utils.rs

proc djb2*(s: openArray[byte]): uint32 =
  var h: uint32 = 5381
  for b in s:
    h = h * 33 + uint32(b)
  h

proc djb2U16*(s: openArray[uint16]): uint32 =
  var h: uint32 = 5381
  for c in s:
    h = h * 33 + uint32(c)
  h

# Compare null-terminated wide string at ptr `a` against slice `b`
# unsafe — reads from raw pointer
proc wideCmp*(a: ptr uint16, b: openArray[uint16]): bool =
  # unsafe
  for i in 0 ..< b.len:
    if cast[ptr uint16](cast[uint](a) + uint(i) * 2)[] != b[i]:
      return false
  true
