import std/unittest
import msrpc/common/[buffers, endian, unicode]

suite "unicode":
  test "ASCII roundtrip":
    let s = "hello"
    let units = toUtf16Units(s)
    check units == @[uint16('h'.ord), uint16('e'.ord), uint16('l'.ord),
                     uint16('l'.ord), uint16('o'.ord)]
    check fromUtf16Units(units) == s

  test "BMP non-ASCII roundtrip":
    let s = "éñ"     # é ñ
    let bytes = toUtf16Bytes(s)
    check bytes == @[0xE9'u8, 0x00, 0xF1, 0x00]
    check fromUtf16Bytes(bytes) == s

  test "surrogate pair (U+1F600)":
    let s = "\xF0\x9F\x98\x80"     # 😀  (U+1F600)
    let bytes = toUtf16Bytes(s)
    check bytes == @[0x3D'u8, 0xD8, 0x00, 0xDE]
    check fromUtf16Bytes(bytes) == s

  test "lone high surrogate decoded as replacement":
    # 0xD800 alone is invalid; we map it to U+FFFD.
    let bytes = @[0x00'u8, 0xD8]
    check fromUtf16Bytes(bytes) == "�"

  test "lone low surrogate decoded as replacement":
    let bytes = @[0x00'u8, 0xDC]
    check fromUtf16Bytes(bytes) == "�"

  test "fromUtf16Bytes rejects odd length":
    expect Utf16DecodeError:
      discard fromUtf16Bytes(@[0x01'u8])

  test "Buffer writeUtf16LE with NUL terminator":
    let b = newBuffer()
    b.writeUtf16LE("hi", nullTerminate = true)
    check b.consumed == @[0x68'u8, 0x00, 0x69, 0x00, 0x00, 0x00]
    let r = newBuffer(b.consumed)
    check r.readUtf16LE(2) == "hi"
    check r.readU16LE() == 0  # consumed NUL
