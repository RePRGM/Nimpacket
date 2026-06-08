## tools/bytediff.nim — byte-by-byte diffing of two captures, with
## protocol awareness to surface field-level mismatches.
##
## Use case: validate wire compatibility with a known-good reference
## implementation (impacket, MIT Kerberos, Wireshark capture) without
## needing a live target. Workflow:
##
##   1. Capture impacket sending the same operation as ours.
##   2. Extract the raw PDU bytes from the pcap.
##   3. Run ``byteDiff(ours, theirs)`` — get a per-byte diff with
##      protocol field annotations on the offsets that differ.
##
## The annotations come from the pretty-printer's protocol decoders —
## we walk both inputs through ``pretty()`` so we can attach the field
## name to each differing byte range.

import std/[strutils, strformat]
import pretty

type
  DiffRun* = object
    offset*: int
    aBytes*: seq[byte]
    bBytes*: seq[byte]
    field*: string         ## name from the pretty-printer if known

  DiffReport* = object
    aLen*: int
    bLen*: int
    runs*: seq[DiffRun]
    aOnlyTail*: seq[byte]  ## bytes only in a (when lengths differ)
    bOnlyTail*: seq[byte]
    protocol*: Protocol

# --- raw byte-diff ------------------------------------------------

proc rawDiff(a, b: openArray[byte]): seq[DiffRun] =
  ## Walk both buffers in lockstep; collect runs of consecutive
  ## mismatched bytes. Adjacent mismatches coalesce into a single run.
  var i = 0
  let n = min(a.len, b.len)
  while i < n:
    if a[i] != b[i]:
      var run = DiffRun(offset: i)
      while i < n and a[i] != b[i]:
        run.aBytes.add a[i]
        run.bBytes.add b[i]
        inc i
      result.add run
    else:
      inc i

# --- field annotation via the pretty-printer ---------------------

proc fieldsForProtocol(d: openArray[byte]; proto: Protocol): seq[PrettyLine] =
  case proto
  of pSmb2: prettySmb2(d)
  of pRpc:  prettyRpc(d)
  of pNtlm: prettyNtlm(d)
  else:     @[]

proc fieldAtOffset(lines: openArray[PrettyLine]; off: int): string =
  ## Find the line whose offset range contains ``off``. Lines are
  ## emitted in order with offsets pointing at field starts; the field
  ## extends until the next line's offset.
  for i in 0 ..< lines.len:
    let nextOff =
      if i + 1 < lines.len: lines[i + 1].offset else: int.high
    if off >= lines[i].offset and off < nextOff:
      return lines[i].name
  result = "(unknown)"

# --- main entry --------------------------------------------------

proc byteDiff*(a, b: openArray[byte]; force: Protocol = pAuto): DiffReport =
  result.aLen = a.len
  result.bLen = b.len
  result.protocol = if force == pAuto: sniffProtocol(a) else: force
  result.runs = rawDiff(a, b)

  # Decode A under the chosen protocol; use its field map for both.
  let lines = fieldsForProtocol(a, result.protocol)
  for i in 0 ..< result.runs.len:
    result.runs[i].field = fieldAtOffset(lines, result.runs[i].offset)

  # Capture any length-mismatch tail.
  if a.len > b.len:
    for i in b.len ..< a.len: result.aOnlyTail.add a[i]
  elif b.len > a.len:
    for i in a.len ..< b.len: result.bOnlyTail.add b[i]

# --- formatting --------------------------------------------------

proc hex(d: openArray[byte]; maxLen = 32): string =
  let n = min(d.len, maxLen)
  for i in 0 ..< n:
    if i > 0 and (i mod 4) == 0: result.add ' '
    result.add toHex(int(d[i]), 2).toLowerAscii
  if d.len > maxLen: result.add fmt" …(+{d.len - maxLen})"

proc formatReport*(r: DiffReport): string =
  if r.runs.len == 0 and r.aOnlyTail.len == 0 and r.bOnlyTail.len == 0:
    return fmt"IDENTICAL ({r.aLen} bytes, protocol = {r.protocol})" & "\n"
  result.add fmt"DIFFER  protocol = {r.protocol}" & "\n"
  result.add fmt"  A: {r.aLen} bytes   B: {r.bLen} bytes" & "\n"
  if r.runs.len > 0:
    result.add fmt"  {r.runs.len} byte-run mismatch(es):" & "\n"
    for run in r.runs:
      result.add fmt"    @0x{run.offset:04x} ({run.field}): " &
                 fmt"A={hex(run.aBytes)}  B={hex(run.bBytes)}" & "\n"
  if r.aOnlyTail.len > 0:
    result.add fmt"  Extra bytes in A: {hex(r.aOnlyTail)}" & "\n"
  if r.bOnlyTail.len > 0:
    result.add fmt"  Extra bytes in B: {hex(r.bOnlyTail)}" & "\n"

# --- convenience helpers ------------------------------------------

proc bytesFromHex*(hexStr: string): seq[byte] =
  var clean = newStringOfCap(hexStr.len)
  for c in hexStr:
    if c in "0123456789abcdefABCDEF": clean.add c
  doAssert clean.len mod 2 == 0, "odd number of hex digits"
  result = newSeq[byte](clean.len div 2)
  for i in 0 ..< result.len:
    result[i] = byte(parseHexInt(clean[2*i .. 2*i+1]))

proc byteDiffFromHex*(aHex, bHex: string;
                       force: Protocol = pAuto): DiffReport =
  byteDiff(bytesFromHex(aHex), bytesFromHex(bHex), force)
