## Loopback test for sendKdcTcp: stand up a tiny TCP listener that
## speaks the RFC 4120 §7.2.2 framing (4-byte BE length prefix), feed
## it canned bytes, verify both directions of the framing.
##
## Doesn't need a real KDC — we just check the wire format.

import std/[unittest, net, os]
import msrpc/auth/kerberos/provider

type KdcArgs = tuple[port: int; reply: seq[byte]]

proc serveOnce(args: KdcArgs) {.thread.} =
  ## Accept one connection, read length-prefixed request, respond with
  ## ``args.reply`` length-prefixed.
  let listener = newSocket()
  listener.setSockOpt(OptReuseAddr, true)
  listener.bindAddr(Port(args.port), "127.0.0.1")
  listener.listen()
  var client: Socket
  listener.accept(client)
  var lenBuf = newString(4)
  var got = 0
  while got < 4:
    let n = client.recv(lenBuf[got].addr, 4 - got)
    if n <= 0: break
    got += n
  let n =
    (int(byte(lenBuf[0])) shl 24) or
    (int(byte(lenBuf[1])) shl 16) or
    (int(byte(lenBuf[2])) shl 8) or
    int(byte(lenBuf[3]))
  var body = newString(n)
  var consumed = 0
  while consumed < n:
    let r = client.recv(body[consumed].addr, n - consumed)
    if r <= 0: break
    consumed += r
  var prefix = newString(4)
  prefix[0] = char((args.reply.len shr 24) and 0xff)
  prefix[1] = char((args.reply.len shr 16) and 0xff)
  prefix[2] = char((args.reply.len shr 8) and 0xff)
  prefix[3] = char(args.reply.len and 0xff)
  var replyStr = newString(args.reply.len)
  for i, b in args.reply: replyStr[i] = char(b)
  client.send(prefix & replyStr)
  client.close()
  listener.close()

var serverThread: Thread[KdcArgs]

proc startEchoKdc(port: int; reply: seq[byte]) =
  createThread(serverThread, serveOnce, (port, reply))
  sleep(100)              # let the listener bind

suite "Kerberos TCP transport (RFC 4120 §7.2.2)":
  test "round-trip a small message through the 4-byte length prefix":
    # Fake AS-REP starting with [APPLICATION 11] = 0x6B
    let canned = @[0x6B'u8, 0x05, 0x30, 0x03, 0x02, 0x01, 0x42]
    startEchoKdc(8088, canned)
    let request = @[0x6A'u8, 0x03, 0x30, 0x01, 0x00]    # fake AS-REQ
    let got = sendKdcTcp("127.0.0.1", 8088, request)
    check got == canned

  test "reply larger than one TCP segment streams cleanly":
    # 8 KB synthetic reply: stresses the recv-loop body
    var canned = newSeq[byte](8192)
    for i in 0 ..< 8192: canned[i] = byte((i * 7 + 3) and 0xff)
    startEchoKdc(8089, canned)
    let got = sendKdcTcp("127.0.0.1", 8089, @[0x01'u8, 0x02, 0x03])
    check got == canned

  test "ktAuto falls back to UDP when TCP is refused":
    ## Point at a port nothing listens on. TCP raises OSError; ktAuto
    ## catches it, falls back to UDP, which times out (no datagram
    ## responder). The exception we see should be KrbProtocolError
    ## from the UDP path, not OSError from the TCP path.
    let p = newKerberosProvider(
      "TEST.LOCAL", "alice", "pw", "127.0.0.1",
      kdcPort = 1, transport = ktAuto)
    expect KrbProtocolError:
      discard sendKdc(p, @[0'u8])
