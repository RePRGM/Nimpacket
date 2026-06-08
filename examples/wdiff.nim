## examples/wdiff.nim — byte-by-byte wire-format diffing.
##
## Usage:
##   nim r examples/wdiff.nim ours.bin theirs.bin
##   nim r examples/wdiff.nim --force=smb2 a.bin b.bin
##
## Or paste hex on stdin separated by "---":
##   { echo "<our hex>"; echo "---"; echo "<their hex>"; } | nim r wdiff.nim

import std/[os, strutils]
import msrpc/tools/[bytediff, pretty]

proc loadFile(path: string): seq[byte] =
  let raw = readFile(path)
  result = newSeq[byte](raw.len)
  for i in 0 ..< raw.len: result[i] = byte(raw[i].ord)

when isMainModule:
  var force = pAuto
  var paths: seq[string] = @[]
  for arg in commandLineParams():
    if arg.startsWith("--force="):
      let v = arg["--force=".len .. ^1]
      case v
      of "smb2": force = pSmb2
      of "dce-rpc", "rpc": force = pRpc
      of "ntlmssp", "ntlm": force = pNtlm
      else: discard
    else:
      paths.add arg

  if paths.len == 2:
    let a = loadFile(paths[0])
    let b = loadFile(paths[1])
    echo formatReport(byteDiff(a, b, force))
  elif paths.len == 0:
    let input = stdin.readAll()
    let parts = input.split("---")
    if parts.len != 2:
      echo "Expected stdin format: '<hex>\\n---\\n<hex>'"
      quit 1
    echo formatReport(byteDiffFromHex(parts[0], parts[1], force))
  else:
    echo "Usage: wdiff [--force=PROTO] [FILE_A FILE_B]"
    quit 1
