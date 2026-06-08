## rpc/transport_np.nim — ncacn_np transport over SMB2.
##
## Wraps an ``SmbPipe`` so the RPC client treats named-pipe access the
## same as TCP. Send writes a frame; recv reads exactly ``n`` bytes
## across as many SMB READs as needed.

import ../smb/client as smb
import transport

type
  NamedPipeTransport* = ref object of Transport
    pipe*: SmbPipe
    pending*: seq[byte]      ## Bytes queued for the next send() to flush
    rbuf*: seq[byte]         ## Bytes received from the last TRANSCEIVE
    rpos*: int

proc newNamedPipeTransport*(p: SmbPipe): NamedPipeTransport =
  result = NamedPipeTransport(pipe: p, pending: @[], rbuf: @[], rpos: 0)

method send*(t: NamedPipeTransport; data: openArray[byte]) =
  ## Buffer the bytes; we actually transmit on the next ``recv`` via
  ## FSCTL_PIPE_TRANSCEIVE so that the round-trip is atomic. This
  ## matches the request/response pattern of every RPC PDU.
  let off = t.pending.len
  t.pending.setLen(off + data.len)
  for i, b in data: t.pending[off + i] = b

method recv*(t: NamedPipeTransport; n: int): seq[byte] =
  if t.rpos >= t.rbuf.len and t.pending.len > 0:
    # Time to fire the round-trip.
    t.rbuf = t.pipe.transceive(t.pending)
    t.pending = @[]
    t.rpos = 0
  result = newSeq[byte](n)
  var got = 0
  while got < n:
    if t.rpos >= t.rbuf.len:
      raise newException(TransportError, "named pipe: out of data")
    let take = min(n - got, t.rbuf.len - t.rpos)
    for i in 0 ..< take:
      result[got + i] = t.rbuf[t.rpos + i]
    t.rpos += take
    got += take

method flush*(t: NamedPipeTransport) =
  ## Send any pending bytes one-way via SMB WRITE (not TRANSCEIVE).
  ## Used after AUTH3, which has no synchronous response — using
  ## TRANSCEIVE there leaves Windows pipes in STATUS_PIPE_BUSY.
  if t.pending.len > 0:
    t.pipe.write(t.pending)
    t.pending = @[]

method close*(t: NamedPipeTransport) =
  try: t.pipe.close()
  except CatchableError: discard
