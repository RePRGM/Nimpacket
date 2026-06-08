import std/unittest
import msrpc/ndr/[context, primitives]

suite "ndr primitives — NDR3":
  test "uint8 roundtrip":
    let bytes = ndrEncode[uint8](0xAB'u8)
    check bytes == @[0xAB'u8]
    check ndrDecode[uint8](bytes) == 0xAB'u8

  test "uint16 LE":
    let bytes = ndrEncode[uint16](0xBEEF'u16)
    check bytes == @[0xEF'u8, 0xBE]
    check ndrDecode[uint16](bytes) == 0xBEEF'u16

  test "uint32 LE":
    let bytes = ndrEncode[uint32](0xDEADBEEF'u32)
    check bytes == @[0xEF'u8, 0xBE, 0xAD, 0xDE]
    check ndrDecode[uint32](bytes) == 0xDEADBEEF'u32

  test "uint64 LE":
    let bytes = ndrEncode[uint64](0x0102030405060708'u64)
    check bytes == @[0x08'u8, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01]
    check ndrDecode[uint64](bytes) == 0x0102030405060708'u64

  test "bool true/false":
    check ndrEncode[bool](true)  == @[0x01'u8]
    check ndrEncode[bool](false) == @[0x00'u8]
    check ndrDecode[bool](@[0x07'u8])  # any non-zero
    check not ndrDecode[bool](@[0x00'u8])

  test "alignment from non-zero offset":
    # u8 then u32 — need 3 pad bytes before the u32
    let c = newNdrEncode(nsNdr)
    var a: uint8 = 0xAA
    var b: uint32 = 0x11223344'u32
    marshal(c, a)
    marshal(c, b)
    let bytes = c.finish()
    check bytes == @[0xAA'u8, 0x00, 0x00, 0x00,
                     0x44, 0x33, 0x22, 0x11]

  test "alignment for hyper (8-byte)":
    let c = newNdrEncode(nsNdr)
    var a: uint8 = 0xAA
    var b: uint64 = 0x1122334455667788'u64
    marshal(c, a)
    marshal(c, b)
    let bytes = c.finish()
    check bytes == @[0xAA'u8, 0,0,0, 0,0,0,0,
                     0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11]
    # decode side
    let dc = newNdrDecode(bytes, nsNdr)
    var aa: uint8
    var bb: uint64
    marshal(dc, aa)
    marshal(dc, bb)
    check aa == 0xAA
    check bb == 0x1122334455667788'u64

suite "ndr primitives — NDR64":
  test "uint64 alignment is still 8":
    let bytes = ndrEncode[uint64](0x0102030405060708'u64, nsNdr64)
    check bytes == @[0x08'u8, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01]
    check ndrDecode[uint64](bytes, nsNdr64) == 0x0102030405060708'u64

  test "u8 + u32 alignment unchanged for scalars":
    # NDR64 does not change scalar alignment; only conformance counts.
    let c = newNdrEncode(nsNdr64)
    var a: uint8 = 1
    var b: uint32 = 2
    marshal(c, a)
    marshal(c, b)
    check c.finish() == @[1'u8, 0,0,0, 2,0,0,0]
