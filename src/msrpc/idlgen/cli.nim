## idlgen/cli.nim — command-line entry for the IDL generator.
##
## Usage:  idlgen <input.idl>  [-o output.nim]
##         idlgen - < input.idl
##
## Builds with: ``nim c -o:idlgen src/msrpc/idlgen/cli.nim``

import std/[os, strutils]
import parser, emitter

proc usage() =
  echo "Usage: idlgen <input.idl|-> [-o output.nim]"
  quit(1)

when isMainModule:
  if paramCount() < 1: usage()
  var inPath = ""
  var outPath = ""
  var i = 1
  while i <= paramCount():
    let p = paramStr(i)
    if p == "-o" and i + 1 <= paramCount():
      outPath = paramStr(i + 1); i += 2
    elif p == "-h" or p == "--help":
      usage()
    else:
      inPath = p; inc i

  let src =
    if inPath == "-": readAll(stdin)
    else: readFile(inPath)
  let pr = newParser(src)
  let ifaces = pr.parseIdl()
  let em = newEmitter()
  let nim = em.emitAll(ifaces)
  if outPath.len == 0:
    stdout.write(nim)
  else:
    writeFile(outPath, nim)
    echo "wrote ", outPath
