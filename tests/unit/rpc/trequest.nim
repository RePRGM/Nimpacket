import std/unittest
import msrpc/common/[buffers, guid]
import msrpc/rpc/[pdu, request]

suite "rpc request":
  test "build then parse round-trip (no object, no auth)":
    let r = RequestPdu(
      callId: 7,
      contextId: 1,
      opnum: 3,
      stub: @[0xDE'u8, 0xAD, 0xBE, 0xEF])
    let bytes = r.buildRequest()
    let p = parseRequest(bytes)
    check p.callId == 7
    check p.contextId == 1
    check p.opnum == 3
    check p.stub == @[0xDE'u8, 0xAD, 0xBE, 0xEF]
    check (not p.hasObject)
    check p.authVerifier.len == 0

  test "build with object UUID":
    let r = RequestPdu(
      callId: 1, contextId: 0, opnum: 1,
      hasObject: true,
      objectUuid: parseUuid("0b1c2170-5732-4e0e-8cd3-d9b16f3b84d7"),
      stub: @[0'u8])
    let bytes = r.buildRequest()
    let b = newBuffer(bytes)
    let hdr = b.readHeader()
    check pfcObjectUuid in hdr.flags
    let p = parseRequest(bytes)
    check p.hasObject
    check p.objectUuid == r.objectUuid
    check p.stub == @[0'u8]

  test "auth verifier preserved on round-trip":
    let r = RequestPdu(
      callId: 1, contextId: 0, opnum: 1,
      stub: @[1'u8, 2, 3, 4],
      authVerifier: @[0xAA'u8, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF])
    let bytes = r.buildRequest()
    let b = newBuffer(bytes)
    let hdr = b.readHeader()
    check hdr.authLen == 6
    let p = parseRequest(bytes)
    check p.stub == @[1'u8, 2, 3, 4]
    check p.authVerifier == r.authVerifier

suite "rpc response":
  test "build then parse round-trip":
    let r = ResponsePdu(callId: 9, contextId: 0, cancelCount: 0,
                       stub: @[0x42'u8, 0x42, 0x42])
    let bytes = r.buildResponse()
    let p = parseResponse(bytes)
    check p.callId == 9
    check p.stub == @[0x42'u8, 0x42, 0x42]

suite "rpc fault":
  test "build then parse":
    let f = FaultPdu(callId: 1, contextId: 0, cancelCount: 0,
                     status: 0xC0000022'u32)
    let bytes = f.buildFault()
    let p = parseFault(bytes)
    check p.status == 0xC0000022'u32
    check p.callId == 1
