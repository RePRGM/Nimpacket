import std/[unittest, strutils]
import msrpc/common/sid

suite "sid":
  # Built-in Administrators: S-1-5-32-544
  const builtinAdminsText = "S-1-5-32-544"
  const builtinAdminsWire: array[16, byte] = [
    0x01'u8, 0x02,                # rev=1, count=2
    0x00, 0x00, 0x00, 0x00, 0x00, 0x05,  # identifier authority = 5 (BE)
    0x20, 0x00, 0x00, 0x00,       # 32
    0x20, 0x02, 0x00, 0x00]       # 544

  test "parse/format round-trip":
    let s = parseSid(builtinAdminsText)
    check $s == builtinAdminsText
    check s.subAuthCount == 2
    check s.identAuthority == 5'u64

  test "wire format matches known SID":
    let s = parseSid(builtinAdminsText)
    check toWire(s) == @builtinAdminsWire

  test "wire roundtrip":
    let s = parseSid(builtinAdminsText)
    check fromWire(toWire(s)) == s

  test "parse rejects missing prefix":
    expect SidParseError: discard parseSid("1-5-32-544")

  test "parse rejects too many sub-authorities":
    var parts = "S-1-5"
    for i in 0 ..< 16:
      parts.add "-1"
    expect SidParseError: discard parseSid(parts)

  test "zero sub-auth count":
    let s = parseSid("S-1-0")
    check s.subAuthCount == 0
    check s.identAuthority == 0
    let bytes = toWire(s)
    check bytes.len == 8
    check fromWire(bytes) == s

  test "wire rejects sub-auth count > 15":
    var bad = @[0x01'u8, 16'u8]
    for _ in 0 ..< 6: bad.add 0
    for _ in 0 ..< 64: bad.add 0
    expect SidParseError: discard fromWire(bad)

  test "high authority parsed as hex":
    let s = parseSid("S-1-0x010000000002-1")
    check s.identAuthority == 0x010000000002'u64
    check ($s).startsWith("S-1-0x")
