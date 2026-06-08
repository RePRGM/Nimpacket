import std/unittest
import msrpc/ndr/[context, primitives, strings]

suite "ndr strings":
  test "bare conformant-varying wide string with NUL":
    let c = newNdrEncode(nsNdr)
    var s = "hi"
    marshalWideStringRaw(c, s, nulTerminated = true)
    let bytes = c.finish()
    # max=3, off=0, actual=3 (u32 each), then "h\0i\0\0\0"
    check bytes == @[
      3'u8,0,0,0,    # max_count
      0,0,0,0,       # offset
      3,0,0,0,       # actual
      0x68,0,        # 'h'
      0x69,0,        # 'i'
      0,0]           # NUL

  test "bare conformant-varying decode strips NUL":
    let payload = @[
      3'u8,0,0,0,
      0,0,0,0,
      3,0,0,0,
      0x68'u8,0, 0x69,0, 0,0]
    let c = newNdrDecode(payload, nsNdr)
    var s = ""
    marshalWideStringRaw(c, s, nulTerminated = true)
    check s == "hi"

  test "empty string":
    let c = newNdrEncode(nsNdr)
    var s = ""
    marshalWideStringRaw(c, s, nulTerminated = true)
    check c.finish() == @[1'u8,0,0,0, 0,0,0,0, 1,0,0,0, 0,0]

  test "RpcUnicodeString encode header + deferred body":
    let c = newNdrEncode(nsNdr)
    var s = rpcUnicodeString("ok", nulTerminated = true)
    marshal(c, s)
    c.drainDeferred()
    let bytes = c.finish()
    # Length=6, MaxLength=6 (= 3 wide chars × 2), then referent id u32,
    # then conformant-varying array body.
    check bytes[0..1] == @[0x06'u8, 0x00]   # Length
    check bytes[2..3] == @[0x06'u8, 0x00]   # MaxLength
    # referent id is non-zero
    check (bytes[4] != 0'u8 or bytes[5] != 0'u8 or bytes[6] != 0'u8 or bytes[7] != 0'u8)
    # array header: max=3, off=0, actual=3, then "o\0k\0\0\0"
    check bytes[8..19] == @[3'u8,0,0,0, 0,0,0,0, 3,0,0,0]
    check bytes[20..25] == @[0x6F'u8,0, 0x6B,0, 0,0]

  test "RpcUnicodeString roundtrip":
    let c = newNdrEncode(nsNdr)
    var s = rpcUnicodeString("hello world")
    marshal(c, s)
    c.drainDeferred()
    let bytes = c.finish()

    let dc = newNdrDecode(bytes, nsNdr)
    var s2: RpcUnicodeString
    marshal(dc, s2)
    dc.drainDeferred()
    check s2.value == "hello world"
    check s2.hasBuffer
    check s2.length == s.length
    check s2.maxLength == s.maxLength

  test "RpcUnicodeString null pointer":
    let c = newNdrEncode(nsNdr)
    var s = RpcUnicodeString(length: 0, maxLength: 0, value: "", hasBuffer: false)
    marshal(c, s)
    c.drainDeferred()
    let bytes = c.finish()
    # Length=0, MaxLength=0, referent=0, no deferred body.
    check bytes == @[0'u8,0, 0,0, 0,0,0,0]

    let dc = newNdrDecode(bytes, nsNdr)
    var s2: RpcUnicodeString
    marshal(dc, s2)
    dc.drainDeferred()
    check (not s2.hasBuffer)
    check s2.value == ""
