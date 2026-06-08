## rpc/transport.nim — abstract transport interface.
##
## The two concrete transports we ship are TCP (ncacn_ip_tcp) and SMB
## named pipes (ncacn_np). Both expose the same simple bytes-in / bytes-
## out interface. A transport must read at least the number of bytes
## requested before returning, raising on short read.

type
  TransportError* = object of CatchableError

  Transport* = ref object of RootObj

method send*(t: Transport; data: openArray[byte]) {.base.} =
  raise newException(TransportError, "send not implemented")

method recv*(t: Transport; n: int): seq[byte] {.base.} =
  raise newException(TransportError, "recv not implemented")

method close*(t: Transport) {.base.} =
  discard

method flush*(t: Transport) {.base.} =
  ## Force any pending bytes onto the wire. Default no-op (TCP doesn't
  ## buffer). Used by named-pipe transport to fire a PDU that has no
  ## response (e.g. AUTH3) so it doesn't get bundled with the next one.
  discard
