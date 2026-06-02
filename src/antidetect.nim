# antidetect.nim — sandbox / analyst environment checks
# Translated from antidetect.rs

import winim

proc isDebuggerPresent*(): bool =
  IsDebuggerPresent() != 0

# CPUID leaf 0x40000000 — hypervisor vendor string
# Returns Some(12-byte vendor) if hypervisor bit (ECX[31]) is set
proc hypervisorVendor*(): (bool, array[12, byte]) =
  var ebx0, ecx0, edx0: uint32
  var ecxLeaf1: uint32

  {.emit: """
    unsigned int eax_out, ebx_out, ecx_out, edx_out;
    __asm__ volatile (
      "push %%rbx\n\t"
      "cpuid\n\t"
      "mov %%ebx, %1\n\t"
      "pop %%rbx"
      : "=a"(eax_out), "=r"(ebx_out), "=c"(ecx_out), "=d"(edx_out)
      : "a"(0x40000000U)
    );
    `ebx0` = ebx_out;
    `ecx0` = ecx_out;
    `edx0` = edx_out;
    unsigned int ecx1;
    __asm__ volatile (
      "push %%rbx\n\t"
      "cpuid\n\t"
      "pop %%rbx"
      : "=c"(ecx1)
      : "a"(1U)
      : "eax", "edx"
    );
    `ecxLeaf1` = ecx1;
  """.}

  if (ecxLeaf1 and (1'u32 shl 31)) == 0:
    return (false, default(array[12, byte]))

  var vendor: array[12, byte]
  copyMem(addr vendor[0], addr ebx0, 4)
  copyMem(addr vendor[4], addr ecx0, 4)
  copyMem(addr vendor[8], addr edx0, 4)
  (true, vendor)

# Returns true if logical CPU count < 2 (single-vCPU sandbox)
proc isLowCoreCount*(): bool =
  var ebxVal: uint32
  {.emit: """
    unsigned int ebx_out;
    __asm__ volatile (
      "push %%rbx\n\t"
      "cpuid\n\t"
      "mov %%ebx, %0\n\t"
      "pop %%rbx"
      : "=r"(ebx_out)
      : "a"(1U)
      : "ecx", "edx"
    );
    `ebxVal` = ebx_out;
  """.}
  let logicalCount = (ebxVal shr 16) and 0xFF'u32
  logicalCount < 2

# Composite check — true if environment looks hostile
proc hostileEnvironment*(): bool =
  if isDebuggerPresent(): return true
  let (hasHv, _) = hypervisorVendor()
  if hasHv: return true
  if isLowCoreCount(): return true
  false
