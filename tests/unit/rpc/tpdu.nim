import std/unittest
import msrpc/common/buffers
import msrpc/rpc/pdu

suite "rpc pdu header":
  test "write then read round-trip":
    let h = PduHeader(
      rpcVersion: 5, rpcMinor: 0,
      pType: ptRequest,
      flags: {pfcFirstFrag, pfcLastFrag},
      dataRep: LittleEndianDrep,
      fragLen: 0x1234'u16,
      authLen: 0x0040'u16,
      callId: 0xDEADBEEF'u32)
    let b = newBuffer()
    b.writeHeader(h)
    check b.consumed.len == HeaderLen
    let r = newBuffer(b.consumed)
    let parsed = r.readHeader()
    check parsed == h

  test "wire layout of a minimal request header":
    let h = defaultHeader(ptRequest, callId = 1)
    var hh = h
    hh.fragLen = 24
    let b = newBuffer()
    b.writeHeader(hh)
    # Bytes:
    #  00: 05 00      rpc version 5.0
    #  02: 00         pType = Request (0)
    #  03: 03         flags = first+last (bits 0,1)
    #  04: 10 00 00 00 DREP (little-endian)
    #  08: 18 00      fragLen = 24
    #  0A: 00 00      authLen = 0
    #  0C: 01 00 00 00 callId = 1
    check b.consumed == @[
      5'u8, 0,
      0,
      0x03,
      0x10, 0, 0, 0,
      24, 0,
      0, 0,
      1, 0, 0, 0]

  test "flags bitfield round-trip":
    let f: PfcFlags = {pfcFirstFrag, pfcLastFrag, pfcObjectUuid}
    let by = flagsToByte(f)
    check by == 0x83'u8     # bits 0,1,7
    check flagsFromByte(by) == f

  test "pType enum covers all spec values":
    # Round-trip every documented PduType.
    for t in PduType.low .. PduType.high:
      var h = defaultHeader(t, 42)
      let b = newBuffer()
      b.writeHeader(h)
      let p = newBuffer(b.consumed).readHeader()
      check p.pType == t

  test "isLittleEndian on LE DREP":
    var h = defaultHeader(ptRequest, 0)
    check h.isLittleEndian
    h.dataRep[0] = 0x00     # big-endian
    check (not h.isLittleEndian)
