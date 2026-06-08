## Tier B integration test: client speaks real PDUs + real TCP socket
## to a mock RPC server running in a background thread.
##
## The mock server understands only what's needed to validate the full
## pipeline: BIND→BIND_ACK and REQUEST→RESPONSE-with-echoed-stub.
## No fragmentation, no auth.

import std/[unittest, net, os, nativesockets, typedthreads]
import msrpc/common/[buffers, guid]
import msrpc/rpc/[pdu, binds, request, transport_tcp, client]

# --- mock server -------------------------------------------------------

proc recvExactly(s: Socket; n: int): seq[byte] =
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

proc serveOne(port: int) {.thread.} =
  ## Accept one connection, handle one BIND + one REQUEST, then exit.
  let listener = newSocket()
  listener.setSockOpt(OptReuseAddr, true)
  listener.bindAddr(Port(port))
  listener.listen(1)
  var client: Socket
  listener.accept(client)
  listener.close()

  # Read BIND PDU
  let header = recvExactly(client, HeaderLen)
  let hb = newBuffer(header)
  let h = hb.readHeader()
  doAssert h.pType == ptBind
  let rest = recvExactly(client, int(h.fragLen) - HeaderLen)
  let fullBind = header & rest
  let bindBody = newBuffer(fullBind)
  discard bindBody.readHeader()
  let bp = bindBody.parseBindBody()

  # Build BIND_ACK accepting first transfer syntax of context 0.
  let accepted = bp.contexts[0].transferSyntaxes[0]
  let ack = BindAckPdu(
    maxXmit: bp.maxXmit, maxRecv: bp.maxRecv, assocGroupId: 0x42,
    secondaryAddress: "\\PIPE\\test",
    results: @[PContextResultEntry(
      result: pcAcceptance, reason: 0, transferSyntax: accepted)])
  sendAll(client, buildBindAck(h.callId, ack))

  # Read REQUEST PDU
  let rh = recvExactly(client, HeaderLen)
  let rb = newBuffer(rh)
  let rhdr = rb.readHeader()
  doAssert rhdr.pType == ptRequest
  let rrest = recvExactly(client, int(rhdr.fragLen) - HeaderLen)
  let req = parseRequest(rh & rrest)

  # Echo stub back as RESPONSE
  let resp = ResponsePdu(
    callId: rhdr.callId,
    contextId: req.contextId,
    cancelCount: 0,
    stub: req.stub)
  sendAll(client, buildResponse(resp))
  client.close()

# --- the test ---------------------------------------------------------

# Pick a port unlikely to collide. Using 0 + getsockname would be ideal
# but the mock-server protocol above is one-shot; a fixed high port is
# good enough for CI.
const testPort = 24817

suite "rpc loopback (Tier B)":
  test "bind + echo call over TCP":
    var th: Thread[int]
    createThread(th, serveOne, testPort)
    # Give the listening thread a moment to bind.
    sleep(50)

    let t = newTcpTransport("127.0.0.1", testPort)
    let raaUuid = parseUuid("0b1c2170-5732-4e0e-8cd3-d9b16f3b84d7")
    let c = connect(t, raaUuid, interfaceVersion = 0)
    check c != nil
    let stub = @[0xCA'u8, 0xFE, 0xBA, 0xBE]
    let echoed = c.call(opnum = 0, stub = stub)
    check echoed == stub
    c.close()
    th.joinThread()
