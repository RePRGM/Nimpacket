## Tier B: fragmented round-trip over TCP.
##
## Sends a stub larger than the negotiated max-fragment size and
## verifies it round-trips through a mock server that responds in
## kind. Unauthenticated path (fragmentation through the auth layer is
## a separate test).

import std/[unittest, net, os, nativesockets, typedthreads]
import msrpc/common/[buffers, guid]
import msrpc/rpc/[pdu, binds, request, transport_tcp, client]

const TestPort = 24821
const SmallFrag = 256'u16          # tiny frag size to force splitting

# --- mock server -----------------------------------------------------

proc recvN(s: Socket; n: int): seq[byte] =
  result = newSeq[byte](n)
  var got = 0
  while got < n:
    var buf = newString(n - got)
    let m = s.recv(buf, n - got)
    if m <= 0:
      raise newException(IOError, "short read")
    for i in 0 ..< m: result[got + i] = byte(buf[i].ord)
    got += m

proc sendAll(s: Socket; data: openArray[byte]) =
  var str = newString(data.len)
  for i, b in data: str[i] = char(b)
  s.send(str)

proc recvPdu(s: Socket): seq[byte] =
  let h = recvN(s, HeaderLen)
  let b = newBuffer(h)
  let hdr = b.readHeader()
  let rest = recvN(s, int(hdr.fragLen) - HeaderLen)
  result = h & rest

proc serveFrag(port: int) {.thread.} =
  let listener = newSocket()
  listener.setSockOpt(OptReuseAddr, true)
  listener.bindAddr(Port(port))
  listener.listen(1)
  var conn: Socket
  listener.accept(conn)
  listener.close()

  # BIND_ACK with tiny frag size to force the client to split.
  let bindBytes = recvPdu(conn)
  let bb = newBuffer(bindBytes)
  let bindHdr = bb.readHeader()
  let bp = bb.parseBindBody()
  let ack = BindAckPdu(
    maxXmit: SmallFrag, maxRecv: SmallFrag, assocGroupId: 0x42,
    secondaryAddress: "",
    results: @[PContextResultEntry(
      result: pcAcceptance, reason: 0,
      transferSyntax: bp.contexts[0].transferSyntaxes[0])])
  sendAll(conn, buildBindAck(bindHdr.callId, ack))

  # Receive request fragments and accumulate the stub.
  var assembled: seq[byte]
  var lastReqHdr: PduHeader
  while true:
    let p = recvPdu(conn)
    let req = parseRequest(p)
    assembled.add req.stub
    lastReqHdr = newBuffer(p).readHeader()
    if pfcLastFrag in lastReqHdr.flags: break

  # Echo back in fragments. Reuse the same chunk size as the request.
  let chunkSize = int(SmallFrag) - HeaderLen - 8   # body overhead
  var off = 0
  var first = true
  while off < assembled.len:
    let take = min(chunkSize, assembled.len - off)
    let isLast = off + take == assembled.len
    var flags: PfcFlags
    if first: flags.incl pfcFirstFrag
    if isLast: flags.incl pfcLastFrag
    let resp = ResponsePdu(
      callId: lastReqHdr.callId, contextId: 0, cancelCount: 0,
      stub: assembled[off ..< off + take])
    sendAll(conn, buildResponse(resp, flags))
    off += take
    first = false
  conn.close()

# --- the test -------------------------------------------------------

suite "rpc loopback fragmented (Tier B)":
  test "request and response both span multiple PDUs":
    var th: Thread[int]
    createThread(th, serveFrag, TestPort)
    sleep(50)

    let t = newTcpTransport("127.0.0.1", TestPort)
    let raaUuid = parseUuid("0b1c2170-5732-4e0e-8cd3-d9b16f3b84d7")
    let c = connect(t, raaUuid, interfaceVersion = 0,
                    maxXmit = SmallFrag, maxRecv = SmallFrag)
    check c.maxXmit == SmallFrag

    # Big payload — multiple fragments at SmallFrag.
    let big = block:
      var s = newSeq[byte](1500)
      for i in 0 ..< 1500: s[i] = byte(i and 0xff)
      s
    let echoed = c.call(opnum = 1, stub = big)
    check echoed == big
    c.close()
    th.joinThread()
