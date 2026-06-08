import std/unittest
import msrpc/common/[buffers, endian]

suite "endian":
  test "u16/u32/u64 LE roundtrip":
    let b = newBuffer()
    b.writeU16LE(0x1234'u16)
    b.writeU32LE(0xDEADBEEF'u32)
    b.writeU64LE(0xCAFEBABE_12345678'u64)
    check b.consumed == @[
      0x34'u8, 0x12,
      0xEF, 0xBE, 0xAD, 0xDE,
      0x78, 0x56, 0x34, 0x12, 0xBE, 0xBA, 0xFE, 0xCA]
    let r = newBuffer(b.consumed)
    check r.readU16LE() == 0x1234'u16
    check r.readU32LE() == 0xDEADBEEF'u32
    check r.readU64LE() == 0xCAFEBABE_12345678'u64

  test "signed roundtrip":
    let b = newBuffer()
    b.writeI16LE(-1'i16)
    b.writeI32LE(-1'i32)
    b.writeI64LE(-1'i64)
    let r = newBuffer(b.consumed)
    check r.readI16LE() == -1'i16
    check r.readI32LE() == -1'i32
    check r.readI64LE() == -1'i64

  test "BE wire format":
    let b = newBuffer()
    b.writeU32BE(0xDEADBEEF'u32)
    check b.consumed == @[0xDE'u8, 0xAD, 0xBE, 0xEF]
    let r = newBuffer(b.consumed)
    check r.readU32BE() == 0xDEADBEEF'u32

  test "U64BE roundtrip and byte order":
    let b = newBuffer()
    b.writeU64BE(0x0102030405060708'u64)
    check b.consumed == @[
      0x01'u8, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]
    let r = newBuffer(b.consumed)
    check r.readU64BE() == 0x0102030405060708'u64

  test "boundary read raises":
    let b = newBuffer([0x01'u8, 0x02])
    expect BufferRangeError:
      discard b.readU32LE()
