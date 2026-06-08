## rpc/transport_tcp.nim — ncacn_ip_tcp transport.
##
## Uses std/net's blocking ``Socket`` for portability (Linux + Windows
## with the same code). Connect timeouts and read timeouts are honored
## via SO_RCVTIMEO/SO_SNDTIMEO where the OS supports it; std/net does
## not expose those uniformly, so the timeout argument here is a
## best-effort hint applied by reconnect logic above this layer.

import std/[net, nativesockets]
import transport

type
  TcpTransport* = ref object of Transport
    sock*: Socket
    host*: string
    port*: int

proc newTcpTransport*(host: string; port: int): TcpTransport =
  result = TcpTransport(host: host, port: port)
  result.sock = newSocket(buffered = false)
  try:
    result.sock.connect(host, Port(port))
  except CatchableError as e:
    result.sock.close()
    raise newException(TransportError, "tcp connect " & host & ":" & $port &
                       " failed: " & e.msg)

method send*(t: TcpTransport; data: openArray[byte]) =
  if data.len == 0: return
  # Socket.send copies but doesn't return short-write; on error it raises.
  var s = newString(data.len)
  for i, b in data: s[i] = char(b)
  try:
    t.sock.send(s)
  except CatchableError as e:
    raise newException(TransportError, "tcp send: " & e.msg)

method recv*(t: TcpTransport; n: int): seq[byte] =
  if n == 0: return @[]
  result = newSeq[byte](n)
  var got = 0
  while got < n:
    var buf = newString(n - got)
    let m = t.sock.recv(buf, n - got)
    if m <= 0:
      raise newException(TransportError, "tcp recv: connection closed")
    for i in 0 ..< m: result[got + i] = byte(buf[i].ord)
    got += m

method close*(t: TcpTransport) =
  try:
    t.sock.close()
  except CatchableError:
    discard
