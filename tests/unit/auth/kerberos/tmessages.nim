## Kerberos message structure tests.

import std/[unittest, strutils, times]
import msrpc/common/buffers
import msrpc/auth/kerberos/messages
import msrpc/auth/spnego/asn1

proc hex(d: openArray[byte]): string =
  for b in d: result.add toHex(int(b), 2).toLowerAscii

suite "Kerberos ASN.1 helpers":
  test "kerberosTimestamp format":
    let t = fromUnix(0)         # 1970-01-01 00:00:00 UTC
    check kerberosTimestamp(t) == "19700101000000Z"

  test "principalName SEQUENCE structure":
    let pn = principalName(NtPrincipal, ["alice"])
    # SEQUENCE { [0] INTEGER 1, [1] SEQUENCE { GeneralString "alice" } }
    let b = newBuffer(pn)
    discard b.derReadTag(tagSequence)
    discard b.derReadTag(ctxConstructed(0))
    let intLen = b.derReadTag(0x02'u8)
    check intLen == 1
    check b.readByte() == 1
    discard b.derReadTag(ctxConstructed(1))
    discard b.derReadTag(tagSequence)
    let strLen = b.derReadTag(0x1B'u8)
    check strLen == 5
    var name = ""
    for _ in 0 ..< strLen: name.add char(b.readByte())
    check name == "alice"

suite "AS-REQ builder":
  test "produces a valid [APPLICATION 10] wrapped SEQUENCE":
    let pdu = buildAsReq(
      realm = "EXAMPLE.COM",
      clientPrincipal = "alice",
      serviceName = "krbtgt",
      nonce = 0x12345678'u32,
      etypes = [18'u32, 17],
      till = "20991231235959Z")
    # First byte should be [APPLICATION 10] constructed = 0x6A
    check pdu[0] == 0x6A'u8

  test "AS-REQ contains the requested etypes":
    let pdu = buildAsReq("E.COM", "u", "krbtgt", 1'u32,
                         [18'u32, 17, 23], "20991231235959Z")
    # The literal etype values appear in the inner INTEGER encodings.
    # Look for the byte sequences 02 01 12 (etype 18) and 02 01 11 (17).
    var hs = hex(pdu)
    check "020112" in hs
    check "020111" in hs
    check "020117" in hs
