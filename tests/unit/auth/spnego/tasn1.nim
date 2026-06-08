import std/[unittest, strutils]
import msrpc/common/buffers
import msrpc/auth/spnego/asn1

proc hex(d: openArray[byte]): string =
  for b in d: result.add toHex(int(b), 2).toLowerAscii

proc unhex(s: string): seq[byte] =
  for i in countup(0, s.len - 1, 2):
    result.add byte(parseHexInt(s[i ..< i+2]))

suite "DER":
  test "short length":
    let b = newBuffer()
    b.derWriteLen(0)
    b.derWriteLen(1)
    b.derWriteLen(127)
    check b.consumed == @[0'u8, 1, 127]

  test "long-form length":
    let b = newBuffer()
    b.derWriteLen(128)            # → 81 80
    b.derWriteLen(255)            # → 81 ff
    b.derWriteLen(256)            # → 82 01 00
    b.derWriteLen(65535)          # → 82 ff ff
    check b.consumed == @[
      0x81'u8, 0x80,
      0x81, 0xff,
      0x82, 0x01, 0x00,
      0x82, 0xff, 0xff]

  test "length round-trip":
    for n in [0, 1, 127, 128, 200, 1000, 65535, 100000]:
      let b = newBuffer()
      b.derWriteLen(n)
      let r = newBuffer(b.consumed)
      check r.derReadLen() == n

suite "DER OID":
  test "SPNEGO 1.3.6.1.5.5.2":
    check hex(derEncodeOid(@SpnegoOidArcs)) == "06062b0601050502"
  test "NTLMSSP 1.3.6.1.4.1.311.2.2.10":
    check hex(derEncodeOid(@NtlmsspOidArcs)) ==
      "060a2b06010401823702020a"
  test "Kerberos 1.2.840.113554.1.2.2":
    check hex(derEncodeOid(@KerberosOidArcs)) ==
      "06092a864886f712010202"
  test "round-trip":
    let raw = derEncodeOid(@NtlmsspOidArcs)
    let b = newBuffer(raw)
    check derParseOid(b) == @NtlmsspOidArcs

  test "OctetString round-trip":
    let raw = derTLV(tagOctetString, @[0xDE'u8, 0xAD, 0xBE, 0xEF])
    check hex(raw) == "0404deadbeef"
    let b = newBuffer(raw)
    check derParseOctetString(b) == @[0xDE'u8, 0xAD, 0xBE, 0xEF]
