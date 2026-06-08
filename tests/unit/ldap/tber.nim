import std/[unittest, strutils]
import msrpc/common/buffers
import msrpc/ldap/ber

proc hex(d: openArray[byte]): string =
  for b in d: result.add toHex(int(b), 2).toLowerAscii

suite "ldap BER":
  test "integer encoding edge cases":
    check hex(berEncodeInt(0))   == "020100"
    check hex(berEncodeInt(127)) == "02017f"
    check hex(berEncodeInt(128)) == "02020080"   # leading zero for positive
    check hex(berEncodeInt(256)) == "02020100"
    check hex(berEncodeInt(-1))  == "0201ff"
    check hex(berEncodeInt(-128))== "020180"

  test "integer round-trip":
    for v in [0'i64, 1, -1, 127, 128, 256, 65535, -32768, 1'i64 shl 30]:
      let enc = berEncodeInt(v)
      let b = newBuffer(enc)
      check berParseInt(b) == v

  test "enumerated retags integer":
    check hex(berEnumerated(2)) == "0a0102"

  test "boolean encoding":
    check hex(berEncodeBool(true))  == "0101ff"
    check hex(berEncodeBool(false)) == "010100"
