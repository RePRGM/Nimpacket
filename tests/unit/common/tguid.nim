import std/unittest
import msrpc/common/guid

suite "guid":
  # MS-RAA interface UUID, from MS-RAA §1.9.
  const raaUuid = "0b1c2170-5732-4e0e-8cd3-d9b16f3b84d7"
  # Microsoft on-wire (mixed-endian) form of the above.
  const raaWire: array[16, byte] = [
    0x70'u8, 0x21, 0x1C, 0x0B,
    0x32, 0x57,
    0x0E, 0x4E,
    0x8C, 0xD3,
    0xD9, 0xB1, 0x6F, 0x3B, 0x84, 0xD7]

  test "string parse roundtrip":
    let u = parseUuid(raaUuid)
    check $u == raaUuid

  test "rejects malformed strings":
    expect GuidParseError: discard parseUuid("not-a-uuid")
    expect GuidParseError: discard parseUuid("0b1c2170_5732-4e0e-8cd3-d9b16f3b84d7")
    expect GuidParseError: discard parseUuid("zzzzzzzz-5732-4e0e-8cd3-d9b16f3b84d7")

  test "accepts brace form":
    let u = parseUuid("{" & raaUuid & "}")
    check $u == raaUuid

  test "wire format (mixed-endian) matches MS-RAA":
    let u = parseUuid(raaUuid)
    check toWire(u) == @raaWire

  test "wire roundtrip":
    let u = parseUuid(raaUuid)
    let bytes = toWire(u)
    check fromWire(bytes) == u

  test "zero UUID":
    var z: Uuid
    check z.isZero
    check $z == "00000000-0000-0000-0000-000000000000"
