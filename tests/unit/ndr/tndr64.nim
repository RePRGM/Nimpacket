## NDR64-specific tests. The protocol differences vs NDR3 are limited to:
##   * conformance / variance counts widen from u32 to u64 (with 8-byte align)
##   * referent ids widen from u32 to u64 (with 8-byte align)
##   * ``hyper`` already had 8-byte alignment in NDR3, so no change there
##
## These tests pin down each of those differences with explicit byte
## vectors so a regression in ``marshalCount`` / ``marshalRefId`` cannot
## go unnoticed.

import std/unittest
import msrpc/common/buffers
import msrpc/ndr/[context, primitives, arrays, strings, pointers]

suite "ndr64 — counts widen to u64":
  test "conformant array u64 max_count":
    let bytes = block:
      let c = newNdrEncode(nsNdr64)
      var arr = @[0xAABB'u16, 0xCCDD]
      marshalConformantArray(c, arr)
      c.finish()
    # u64 max_count (2) + 4-byte align satisfied + two u16
    check bytes == @[
      2'u8,0,0,0, 0,0,0,0,
      0xBB, 0xAA, 0xDD, 0xCC]

    let dc = newNdrDecode(bytes, nsNdr64)
    var arr2: seq[uint16]
    marshalConformantArray(dc, arr2)
    check arr2 == @[0xAABB'u16, 0xCCDD]

  test "varying array u64 offset + actual":
    let bytes = block:
      let c = newNdrEncode(nsNdr64)
      var arr = @[1'u32, 2]
      var off: uint64 = 0
      var cnt: uint64 = 2
      marshalVaryingArray(c, arr, off, cnt)
      c.finish()
    check bytes == @[
      0'u8,0,0,0, 0,0,0,0,
      2,0,0,0, 0,0,0,0,
      1,0,0,0, 2,0,0,0]

  test "conformant-varying with three u64 headers":
    let bytes = block:
      let c = newNdrEncode(nsNdr64)
      var arr = @[42'u32]
      var mc: uint64 = 1
      var off: uint64 = 0
      var cnt: uint64 = 1
      marshalConformantVaryingArray(c, arr, mc, off, cnt)
      c.finish()
    check bytes == @[
      1'u8,0,0,0, 0,0,0,0,    # max_count u64
      0,0,0,0, 0,0,0,0,       # offset u64
      1,0,0,0, 0,0,0,0,       # actual u64
      42,0,0,0]

suite "ndr64 — referent ids widen to u64":
  test "top-level unique pointer with u64 refid":
    let c = newNdrEncode(nsNdr64)
    var p: ref uint32
    new p
    p[] = 0xDEAD'u32
    marshalTopUniquePointer(c, p)
    c.drainDeferred()
    let bytes = c.finish()
    # u64 referent id (non-zero) + aligned u32 payload
    check bytes.len == 12
    check bytes[8..11] == @[0xAD'u8, 0xDE, 0, 0]
    # at least one of the refid bytes is non-zero
    var refIdNonZero = false
    for i in 0..7:
      if bytes[i] != 0'u8: refIdNonZero = true
    check refIdNonZero

    let dc = newNdrDecode(bytes, nsNdr64)
    var p2: ref uint32
    marshalTopUniquePointer(dc, p2)
    dc.drainDeferred()
    check p2 != nil and p2[] == 0xDEAD'u32

  test "null unique pointer is u64 zero":
    let c = newNdrEncode(nsNdr64)
    var p: ref uint32 = nil
    marshalTopUniquePointer(c, p)
    c.drainDeferred()
    check c.finish() == @[0'u8,0,0,0, 0,0,0,0]

suite "ndr64 — strings":
  test "bare wide string uses u64 counts":
    let c = newNdrEncode(nsNdr64)
    var s = "Hi"
    marshalWideStringRaw(c, s, nulTerminated = true)
    let bytes = c.finish()
    # max=3 u64, off=0 u64, actual=3 u64, then "H\0i\0\0\0"
    check bytes == @[
      3'u8,0,0,0, 0,0,0,0,
      0,0,0,0, 0,0,0,0,
      3,0,0,0, 0,0,0,0,
      0x48, 0, 0x69, 0, 0, 0]

    let dc = newNdrDecode(bytes, nsNdr64)
    var s2 = ""
    marshalWideStringRaw(dc, s2, nulTerminated = true)
    check s2 == "Hi"

  test "RpcUnicodeString roundtrip under NDR64":
    let bytes = block:
      let c = newNdrEncode(nsNdr64)
      var s = rpcUnicodeString("test")
      marshal(c, s)
      c.drainDeferred()
      c.finish()
    let dc = newNdrDecode(bytes, nsNdr64)
    var s2: RpcUnicodeString
    marshal(dc, s2)
    dc.drainDeferred()
    check s2.value == "test"
    check s2.hasBuffer

suite "ndr64 — primitive alignment unchanged":
  test "u8 then u32 is still 4-byte-aligned":
    let c = newNdrEncode(nsNdr64)
    var a: uint8 = 0xFF
    var b: uint32 = 0x12345678'u32
    marshal(c, a)
    marshal(c, b)
    check c.finish() == @[0xFF'u8, 0,0,0, 0x78, 0x56, 0x34, 0x12]

  test "hyper alignment is still 8 (matches NDR3)":
    let c = newNdrEncode(nsNdr64)
    var a: uint8 = 1
    var b: uint64 = 0x1122334455667788'u64
    marshal(c, a)
    marshal(c, b)
    check c.finish() == @[
      1'u8, 0,0,0, 0,0,0,0,
      0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11]
