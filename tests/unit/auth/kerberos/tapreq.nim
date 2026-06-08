import std/[unittest, strutils, times]
import msrpc/common/buffers
import msrpc/auth/spnego/asn1
import msrpc/auth/kerberos/[rc4, apreq]

proc hex(d: openArray[byte]): string =
  for b in d: result.add toHex(int(b), 2).toLowerAscii

suite "Kerberos AP-REQ":
  test "AP-REQ outer tag is [APPLICATION 14]":
    let sessionKey = rc4HmacStringToKey("Password")
    let ticket = @[0x61'u8, 0x02, 0x30, 0x00]   # minimal placeholder
    let ap = buildApReq(sessionKey, ticket, "EXAMPLE.COM", "alice",
                        fromUnix(1700000000))
    check ap[0] == 0x6E'u8     # [APPLICATION 14] constructed

  test "AP-REQ contains the ticket bytes verbatim":
    let sessionKey = rc4HmacStringToKey("Password")
    let ticket = @[0x61'u8, 0x04, 0x30, 0x02, 0xAB, 0xCD]
    let ap = buildApReq(sessionKey, ticket, "E.COM", "u",
                        fromUnix(1))
    let hs = hex(ap)
    check "6104300" & "2abcd" in hs

  test "GSS-API wrap adds [APP 0] + Kerberos OID + TOK_ID":
    let sessionKey = rc4HmacStringToKey("Password")
    let ticket = @[0x61'u8, 0x02, 0x30, 0x00]
    let ap = buildApReq(sessionKey, ticket, "R", "u", fromUnix(1))
    let wrapped = wrapGssApReq(ap)
    check wrapped[0] == 0x60'u8     # [APPLICATION 0] IMPLICIT
    # Kerberos OID 1.2.840.113554.1.2.2 → 06 09 2a 86 48 86 f7 12 01 02 02
    check "06092a864886f71201" & "0202" in hex(wrapped)
    # TOK_ID 0x01 0x00 appears immediately after the OID.
    # Just confirm both bytes are present.
    check "0100" in hex(wrapped)
