## Smoke tests for the wire-format pretty-printer. Round-trip: build a
## PDU with our existing builders, run it through pretty(), check the
## output names the expected fields.

import std/[unittest, strutils]
import msrpc/common/buffers
import msrpc/rpc/[pdu, request]
import msrpc/smb/header as smbHeader
import msrpc/tools/pretty

suite "Wire-format pretty-printer":
  test "sniffs an SMB2 PDU by magic":
    let bytes = @[0xFE'u8, byte('S'), byte('M'), byte('B'), 0x40, 0]
    check sniffProtocol(bytes) == pSmb2

  test "sniffs DCE-RPC v5 + LE DREP":
    let bytes = @[0x05'u8, 0x00, 0x00, 0x00,        # ver + ptype + flags
                  0x10, 0x00, 0x00, 0x00]            # LE DREP
    check sniffProtocol(bytes) == pRpc

  test "sniffs NTLMSSP by magic":
    let bytes = @[byte('N'), byte('T'), byte('L'), byte('M'),
                  byte('S'), byte('S'), byte('P'), 0'u8, 0x03, 0, 0, 0]
    check sniffProtocol(bytes) == pNtlm

  test "sniffs Kerberos AS-REP outer tag":
    let bytes = @[0x6B'u8, 0x10, 0x30, 0x0E]
    check sniffProtocol(bytes) == pKrb

  test "pretty-prints an SMB2 header":
    let hb = newBuffer()
    hb.writeHeader(Smb2Header(creditCharge: 1, command: cmdNegotiate,
                              creditsRequested: 64, messageId: 7,
                              treeId: 0, sessionId: 0xCAFE'u64))
    let out_str = pretty(hb.consumed)
    check "Protocol: SMB2" in out_str
    check "Command" in out_str
    check "NEGOTIATE" in out_str
    check "MessageId" in out_str
    check "cafe" in out_str.toLowerAscii          # session id surfaces somewhere

  test "pretty-prints a DCE-RPC REQUEST":
    let req = RequestPdu(callId: 99, contextId: 0, opnum: 3,
                         stub: @[byte 0x01, 0x02, 0x03, 0x04])
    let pduBytes = req.buildRequest({pfcFirstFrag, pfcLastFrag})
    let out_str = pretty(pduBytes)
    check "Protocol: DCE-RPC" in out_str
    check "REQUEST" in out_str
    check "frag_length" in out_str
    check "FIRST" in out_str and "LAST" in out_str

  test "prettyFromHex tolerates whitespace and case":
    # 64-byte SMB2 header skeleton (NEGOTIATE).
    var hb = newBuffer()
    hb.writeHeader(Smb2Header(creditCharge: 1, command: cmdNegotiate,
                              creditsRequested: 1, messageId: 0))
    var hexStr = ""
    for b in hb.consumed: hexStr.add toHex(int(b), 2)
    # Insert noise: spaces, tabs, capital letters.
    let noised = hexStr.toUpperAscii.replace("0", " 0 ").replace("F", "\tF\t")
    let out_str = prettyFromHex(noised)
    check "SMB2" in out_str
    check "StructureSize" in out_str

  test "prettyFromHex flags odd-length input":
    let bad = prettyFromHex("01234")
    check "odd number" in bad
