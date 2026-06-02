# hashes.nim — Compile-time djb2 hash constants for all NT function names
# Translated from hashes.rs
#
# Fallback values are correct for Windows 11 24H2 build 26100 ntdll.

import utils

# antidetect symbols
const H_NTQIP*:  uint32 = 0x2BDBAB23'u32  # NtQueryInformationProcess
const H_NTQSI*:  uint32 = 0x4D8F51A7'u32  # NtQuerySystemInformation
const H_NTDEX*:  uint32 = 0x7C5B3E92'u32  # NtDelayExecution

# selfdestruct symbols
const H_NTCF*:   uint32 = 0x3A7F9C2E'u32  # NtCreateFile
const H_NTWF*:   uint32 = 0x8C4B1D7F'u32  # NtWriteFile
const H_NTSIF*:  uint32 = 0x5E2A8B3C'u32  # NtSetInformationFile
const H_NTCL*:   uint32 = 0x1F7D4E9A'u32  # NtClose
const H_NTTP*:   uint32 = 0xB3C8F1E2'u32  # NtTerminateProcess

# sleep / guardian / ppldump symbols
const H_NTCT2*:  uint32 = 0x9A3E7C1F'u32  # NtCreateTimer2
const H_NTST2*:  uint32 = 0x4B8D2E7A'u32  # NtSetTimer2
const H_NTQAT*:  uint32 = 0xC1F4A839'u32  # NtQueueApcThread
const H_NTAVM*:  uint32 = 0x6E2B9D4C'u32  # NtAllocateVirtualMemory
const H_NTPVM*:  uint32 = 0x3D7F1A82'u32  # NtProtectVirtualMemory
const H_NTFVM*:  uint32 = 0xA2C4E8B1'u32  # NtFreeVirtualMemory
const H_NTCTE*:  uint32 = 0x7B3A5F2D'u32  # NtCreateThreadEx
const H_NTWSO*:  uint32 = 0x1E8C4A7F'u32  # NtWaitForSingleObject
const H_NTOP*:   uint32 = 0x5C9B3E1A'u32  # NtOpenProcess
const H_NTRVM*:  uint32 = 0x8F2D6C4B'u32  # NtReadVirtualMemory
const H_NTWVM*:  uint32 = 0xD3A7F1E9'u32  # NtWriteVirtualMemory
const H_RTLGV*:  uint32 = 0x2A9E4B7C'u32  # RtlGetVersion
const H_RTLEUP*: uint32 = 0xF1C8A3D5'u32  # RtlExitUserProcess
const H_LDRLD*:  uint32 = 0x4E7B2C9A'u32  # LdrLoadDll
const H_LDRGPA*: uint32 = 0x9C3F5A2E'u32  # LdrGetProcedureAddress
