# ssn_audit.nim — Live ntdll SSN extractor + fallback table validator
#
# Diagnostic utility: walks ntdll EAT, extracts SSNs, cross-checks fallback table.

import utils, indirect_syscall

type
  SsnEntry* = object
    name*:        string
    nameHash*:    uint32
    ssn*:         uint16
    syscallAddr*: uint
    stubAddr*:    uint

proc findNtdllBase*(): pointer =
  # unsafe — PEB walk
  var peb: uint
  {.emit: """__asm__ volatile ("movq %%gs:0x60, %0" : "=r"(`peb`));""".}
  let ldr      = cast[ptr uint](peb + 0x18)[]
  let listHead = cast[ptr uint](ldr + 0x10)
  var entry    = listHead[]           # flink
  entry        = cast[ptr uint](entry)[]  # [0] = exe (skip)
  entry        = cast[ptr uint](entry)[]  # [1] = ntdll
  let base     = cast[ptr uint](entry + 0x20)[]
  if base == 0: nil else: cast[pointer](base)

proc walkNtdllEat*(base: pointer): seq[SsnEntry] =
  # unsafe
  result = @[]
  let bp = cast[uint](base)
  if cast[ptr uint16](bp)[] != 0x5A4D'u16: return

  let eLfanew  = uint(cast[ptr uint32](bp + 0x3C)[])
  let nt       = bp + eLfanew
  let optOff   = uint(4 + 20)
  let expRva   = uint(cast[ptr uint32](nt + optOff + 112)[])
  if expRva == 0: return

  let export_   = bp + expRva
  let nNames    = int(cast[ptr uint32](export_ + 0x18)[])
  let addrRva   = uint(cast[ptr uint32](export_ + 0x1C)[])
  let nameRva   = uint(cast[ptr uint32](export_ + 0x20)[])
  let ordRva    = uint(cast[ptr uint32](export_ + 0x24)[])
  let addrTbl   = cast[ptr uint32](bp + addrRva)
  let nameTbl   = cast[ptr uint32](bp + nameRva)
  let ordTbl    = cast[ptr uint16](bp + ordRva)

  for i in 0 ..< nNames:
    let nameOff = uint(cast[ptr uint32](cast[uint](nameTbl) + uint(i) * 4)[])
    let namePtr = cast[ptr byte](bp + nameOff)
    var length  = 0
    while cast[ptr byte](cast[uint](namePtr) + uint(length))[] != 0: inc length
    var nameBytes = newSeq[byte](length)
    for j in 0 ..< length:
      nameBytes[j] = cast[ptr byte](cast[uint](namePtr) + uint(j))[]

    let startsWithNt = length >= 2 and nameBytes[0] == byte('N') and nameBytes[1] == byte('t')
    let startsWithZw = length >= 2 and nameBytes[0] == byte('Z') and nameBytes[1] == byte('w')
    if not (startsWithNt or startsWithZw): continue

    let nameStr = cast[string](nameBytes)
    let ord     = uint(cast[ptr uint16](cast[uint](ordTbl) + uint(i) * 2)[])
    let fnRva   = uint(cast[ptr uint32](cast[uint](addrTbl) + ord * 4)[])
    let stubAddr = bp + fnRva
    let stubPtr  = cast[ptr byte](stubAddr)
    let h        = djb2(nameBytes)

    let (ok, stub) = parseStub(stubPtr, h)
    if ok:
      result.add(SsnEntry(
        name:        nameStr,
        nameHash:    h,
        ssn:         stub.ssn,
        syscallAddr: stub.syscallAddr,
        stubAddr:    stubAddr))

  result.sort(proc(a, b: SsnEntry): int = int(a.ssn) - int(b.ssn))

proc printReport*(entries: seq[SsnEntry]) =
  let build = getBuildNumber()
  echo "\n=== SSN Audit Report (build ", build, ") ==="
  echo alignLeft("Function", 48), "   SSN  SyscallAddr        StubAddr"
  echo "-".repeat(96)
  for e in entries:
    echo alignLeft(e.name, 48), "  ", e.ssn.toHex(4), "  ",
         "0x" & e.syscallAddr.toHex(16), "  ",
         "0x" & e.stubAddr.toHex(16)
  echo "\nTotal: ", entries.len, " syscalls"

proc runAudit*() =
  let base = findNtdllBase()
  if base == nil:
    echo "[ssn_audit] failed to resolve ntdll base"
    return
  let entries = walkNtdllEat(base)
  printReport(entries)

when isMainModule:
  runAudit()
