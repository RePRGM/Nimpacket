## Tier B: CLDAP exchange against a Nim-backed mock UDP server.
##
## The mock server listens on UDP/127.0.0.1:port, parses a SearchRequest,
## and replies with one SearchResultEntry (carrying a synthetic
## ``netlogon`` attribute) followed by a SearchResultDone. The client
## exercises the full CldapClient + cldapSearch path including
## datagram-by-datagram reassembly.

import std/[unittest, net, os, typedthreads, nativesockets]
import msrpc/common/buffers
import msrpc/ldap/[messages, cldap, ber]

const TestPort = 24823

# --- mock server thread ---------------------------------------------

proc mockServer(port: int) {.thread.} =
  let s = newSocket(AF_INET, SOCK_DGRAM, IPPROTO_UDP, buffered = false)
  s.setSockOpt(OptReuseAddr, true)
  s.bindAddr(Port(port), "127.0.0.1")

  var data = newString(8192)
  var sender = ""
  var senderPort: Port
  let n = s.recvFrom(data, 8192, sender, senderPort)
  doAssert n > 0, "mock server received empty datagram"
  data.setLen(n)
  var raw = newSeq[byte](n)
  for i in 0 ..< n: raw[i] = byte(data[i].ord)
  let req = parseLdapMessage(raw)

  # Build SearchResultEntry { dn="", attrs=[("Echo", request.opTag)] }
  # We don't bother fabricating a parseable netlogon blob; instead we
  # echo back the messageId and a simple attribute the test can verify.
  let entryInner = newBuffer()
  entryInner.writeBytes(derTLV(tagOctetString, @[]))         # DN = ""
  # attributes: SEQUENCE OF PartialAttribute
  let attrs = newBuffer()
  let attr1 = newBuffer()
  attr1.writeBytes(derTLV(tagOctetString,
                          cast[seq[byte]](@"Echo")))
  # SET OF values
  let valSet = newBuffer()
  valSet.writeBytes(derTLV(tagOctetString,
                            @[0xDE'u8, 0xAD, 0xBE, 0xEF]))
  attr1.writeBytes(derTLV(tagSet, valSet.consumed))
  attrs.writeBytes(derTLV(tagSequence, attr1.consumed))
  entryInner.writeBytes(derTLV(tagSequence, attrs.consumed))
  let searchEntry = derTLV(appConstructed(4), entryInner.consumed)
  # Wrap as LDAPMessage with the request's messageId
  let m1 = newBuffer()
  m1.writeBytes(berEncodeInt(int64(req.messageId)))
  m1.writeBytes(searchEntry)
  let pdu1 = derTLV(tagSequence, m1.consumed)

  # SearchResultDone { resultCode=success, matchedDN="", diag="" }
  let doneInner = newBuffer()
  doneInner.writeBytes(berEnumerated(0))                    # success
  doneInner.writeBytes(derTLV(tagOctetString, @[]))
  doneInner.writeBytes(derTLV(tagOctetString, @[]))
  let doneOp = derTLV(appConstructed(5), doneInner.consumed)
  let m2 = newBuffer()
  m2.writeBytes(berEncodeInt(int64(req.messageId)))
  m2.writeBytes(doneOp)
  let pdu2 = derTLV(tagSequence, m2.consumed)

  proc send(b: openArray[byte]) =
    var str = newString(b.len)
    for i, x in b: str[i] = char(x)
    s.sendTo(sender, senderPort, str)

  send(pdu1)
  send(pdu2)
  s.close()

# --- the test ------------------------------------------------------

suite "cldap loopback":
  test "send Search → receive entry + done":
    var th: Thread[int]
    createThread(th, mockServer, TestPort)
    sleep(50)

    let c = newCldapClient("127.0.0.1", TestPort, timeoutMs = 2000)
    let filter = buildPresenceFilter("objectClass")
    let r = c.cldapSearch(baseDn = "", scope = lsBaseObject,
                          filter = filter,
                          attributes = @["Echo"])
    c.close()
    th.joinThread()

    check r.entries.len == 1
    check r.entries[0].dn == ""
    check r.entries[0].attributes.len == 1
    check r.entries[0].attributes[0].name == "Echo"
    check r.entries[0].attributes[0].values[0] == @[0xDE'u8, 0xAD, 0xBE, 0xEF]
    check r.done.resultCode == 0
