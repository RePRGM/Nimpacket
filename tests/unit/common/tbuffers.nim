import std/unittest
import msrpc/common/buffers

suite "buffers":
  test "writeBytes/readBytes roundtrip":
    let b = newBuffer()
    b.writeBytes([0xDE'u8, 0xAD, 0xBE, 0xEF])
    check b.consumed == @[0xDE'u8, 0xAD, 0xBE, 0xEF]
    let r = newBuffer(b.consumed)
    check r.readBytes(4) == @[0xDE'u8, 0xAD, 0xBE, 0xEF]
    check r.atEnd

  test "readBytes past end raises":
    let b = newBuffer([0x01'u8, 0x02])
    expect BufferRangeError:
      discard b.readBytes(3)

  test "negative read raises":
    let b = newBuffer([0x01'u8])
    expect BufferRangeError:
      discard b.readBytes(-1)

  test "skip / seek bounds":
    let b = newBuffer([1'u8, 2, 3])
    b.skip(2); check b.pos == 2
    expect BufferRangeError: b.skip(5)
    b.seek(0); check b.pos == 0
    expect BufferRangeError: b.seek(99)

  test "alignTo from non-zero":
    let b = newBuffer()
    b.writeBytes([1'u8])
    b.alignTo(4)
    check b.pos == 4
    check b.data[1..3] == @[0'u8, 0, 0]
    b.alignTo(4)  # no-op when already aligned
    check b.pos == 4

  test "alignTo on read does not grow":
    let b = newBuffer([1'u8, 0, 0, 0, 5, 6, 7, 8])
    discard b.readByte()
    b.alignTo(4)
    check b.pos == 4
    check b.readByte() == 5

  test "alignTo with bad n asserts":
    let b = newBuffer()
    when not defined(release):
      expect AssertionDefect:
        b.alignTo(3)

  test "alignedPos formula":
    check alignedPos(0, 4) == 0
    check alignedPos(1, 4) == 4
    check alignedPos(4, 4) == 4
    check alignedPos(5, 8) == 8
    check alignedPos(9, 1) == 9
