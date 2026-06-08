## Tests for the byte-diffing harness.

import std/[unittest, strutils, sugar]
import msrpc/common/buffers
import msrpc/smb/header as smbHeader
import msrpc/tools/bytediff
import msrpc/tools/pretty

proc buildHeaderHex(messageId: uint64; treeId: uint32 = 0;
                    sessionId: uint64 = 0): string =
  let hb = newBuffer()
  hb.writeHeader(Smb2Header(creditCharge: 1, command: cmdNegotiate,
                             creditsRequested: 64, messageId: messageId,
                             treeId: treeId, sessionId: sessionId))
  for b in hb.consumed: result.add toHex(int(b), 2)

suite "bytediff: raw byte differences":
  test "identical inputs report no runs":
    let a = bytesFromHex(buildHeaderHex(7))
    let b = bytesFromHex(buildHeaderHex(7))
    let r = byteDiff(a, b)
    check r.runs.len == 0
    check r.aOnlyTail.len == 0
    check r.bOnlyTail.len == 0
    check "IDENTICAL" in formatReport(r)

  test "different MessageId surfaces one diff run":
    let a = bytesFromHex(buildHeaderHex(7))
    let b = bytesFromHex(buildHeaderHex(99))
    let r = byteDiff(a, b)
    check r.runs.len >= 1
    # The mismatch starts within the MessageId field (offset 24..31).
    check r.runs[0].offset >= 24 and r.runs[0].offset < 32

  test "field annotation names the SMB2 field that differs":
    let a = bytesFromHex(buildHeaderHex(7))
    let b = bytesFromHex(buildHeaderHex(99))
    let r = byteDiff(a, b)
    let fields = collect:
      for run in r.runs: run.field
    # At least one mismatched run should be annotated as MessageId.
    check "MessageId" in fields

  test "different SessionIds annotate the SessionId field":
    let a = bytesFromHex(buildHeaderHex(1, sessionId = 0xAAAA))
    let b = bytesFromHex(buildHeaderHex(1, sessionId = 0xBBBB))
    let r = byteDiff(a, b)
    let fields = collect:
      for run in r.runs: run.field
    check "SessionId" in fields

  test "length mismatch captures the tail":
    let a = bytesFromHex("01020304")
    let b = bytesFromHex("0102")
    let r = byteDiff(a, b)
    check r.aLen == 4
    check r.bLen == 2
    check r.aOnlyTail == @[byte 0x03, 0x04]

  test "formatReport prints the per-run mismatch":
    let a = bytesFromHex(buildHeaderHex(7))
    let b = bytesFromHex(buildHeaderHex(99))
    let out_str = formatReport(byteDiff(a, b))
    check "DIFFER" in out_str
    check "MessageId" in out_str

  test "byteDiffFromHex accepts whitespace":
    let r = byteDiffFromHex("01 02 03", "01 02 04")
    check r.runs.len == 1
    check r.runs[0].offset == 2

