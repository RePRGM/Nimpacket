## examples/decode.nim — paste hex bytes from any MS-RPC capture and
## see them decoded. Auto-detects the protocol.
##
## Usage:
##   echo "fe534d42 4000 …" | nim r examples/decode.nim
##   nim r examples/decode.nim path/to/binary.dat
##   nim r examples/decode.nim --force=smb2 path/to/raw.bin

import std/[os, strutils]
import msrpc/tools/pretty

proc usage() =
  echo "Usage: decode [--force=smb2|dce-rpc|ntlmssp|kerberos|ldap] [FILE]"
  echo "       echo '<hex>' | decode"
  quit 1

when isMainModule:
  var force = pAuto
  var file = ""
  for arg in commandLineParams():
    if arg.startsWith("--force="):
      let v = arg["--force=".len .. ^1]
      case v
      of "smb2": force = pSmb2
      of "dce-rpc", "rpc": force = pRpc
      of "ntlmssp", "ntlm": force = pNtlm
      of "kerberos", "krb": force = pKrb
      of "ldap": force = pLdap
      else: usage()
    elif arg in ["-h", "--help"]: usage()
    elif file.len == 0: file = arg
    else: usage()

  if file.len > 0:
    var data = newSeq[byte](0)
    let raw = readFile(file)
    data.setLen(raw.len)
    for i in 0 ..< raw.len: data[i] = byte(raw[i].ord)
    echo pretty(data, force)
  else:
    let input = stdin.readAll()
    echo prettyFromHex(input, force)
