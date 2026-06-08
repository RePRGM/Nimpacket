import std/[unittest, strutils]
import msrpc/ldap/[ber, messages]

proc hex(d: openArray[byte]): string =
  for b in d: result.add toHex(int(b), 2).toLowerAscii

suite "ldap messages":
  test "anonymous BindRequest layout":
    let pdu = buildBindRequest(messageId = 1, bindDn = "", password = "")
    # SEQUENCE { 0201 01  60 07 0201 03 04 00 80 00 }
    check hex(pdu) == "300c02010160070201030400" & "8000"

  test "BindResponse parses":
    # Build a fake BindResponse: outer SEQ { msgID 1, [APP 1] { 0A0100 0400 0400 } }
    # which means resultCode=0(success), no matchedDN, no diagMessage.
    let respBody = "\x0a\x01\x00\x04\x00\x04\x00"
    let inner = "\x02\x01\x01\x61\x07" & respBody
    let pdu = "\x30" & char(inner.len.byte.ord) & inner
    var bytes = newSeq[byte](pdu.len)
    for i, ch in pdu: bytes[i] = byte(ch.ord)
    let m = parseLdapMessage(bytes)
    check m.kind == lokBindResponse
    check m.messageId == 1
    check m.doneResult.resultCode == 0

  test "SearchRequest contains the filter bytes":
    let filt = buildPresenceFilter("objectClass")
    let pdu = buildSearchRequest(2, "dc=example,dc=com", lsWholeSubtree,
                                  filter = filt,
                                  attributes = @["cn", "sn"])
    let h = hex(pdu)
    # Should contain the filter bytes (87 0b 6f 62 6a 65 63 74 43 6c 61 73 73)
    check "870b6f626a656374436c617373" in h
    # Should contain message ID 2.
    check h.startsWith("30")    # outer SEQUENCE
    # baseObject "dc=example,dc=com" → 0411 6463 3d65 ...
    check "0411646c" notin h   # wrong
    check "0411" & "64633d6578616d706c652c64633d636f6d" in h

  test "presence filter byte layout":
    check hex(buildPresenceFilter("foo")) == "8703666f6f"

  test "equality filter byte layout":
    let f = buildEqualityFilter("cn", cast[seq[byte]](@"alice"))
    # context-3 constructed { 04 02 'cn' 04 05 'alice' }
    check hex(f) == "a30b0402636e040561" & "6c696365"

  test "unbind layout":
    check hex(buildUnbindRequest(7)) == "300502010742" & "00"
