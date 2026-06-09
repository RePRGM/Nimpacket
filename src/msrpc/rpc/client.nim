## rpc/client.nim — connection-oriented RPC client.
##
## Supports two modes:
##
##   1. Unauthenticated: plain BIND → REQUEST → RESPONSE.
##   2. Authenticated: BIND-with-auth → BIND_ACK (carrying server token)
##      → AUTH3 → signed/sealed REQUEST → signed/sealed RESPONSE.
##
## The auth path uses ``NtlmProvider`` directly today; a more generic
## ``AuthProvider``-based path will follow once Kerberos is added.

import ../common/[buffers, guid]
import ../auth/ntlm/provider
import pdu, binds, request, transport, auth, wrapper, fragment

type
  RpcClientError* = object of CatchableError

  RpcClient* = ref object
    transport*: Transport
    interfaceUuid*: Uuid
    interfaceVersion*: uint32
    transferSyntax*: SyntaxId
    contextId*: uint16
    callId*: uint32
    maxXmit*, maxRecv*: uint16
    auth*: AuthProvider             ## nil ⇒ unauthenticated
    authLevel*: AuthnLevel          ## ignored when ``auth`` is nil
    authContextId*: uint32

proc nextCallId(c: RpcClient): uint32 =
  result = c.callId
  inc c.callId

proc readPdu(c: RpcClient): seq[byte] =
  let header = c.transport.recv(HeaderLen)
  let b = newBuffer(header)
  let h = b.readHeader()
  if h.fragLen < uint16(HeaderLen):
    raise newException(RpcClientError, "fragLen < HeaderLen")
  let rest = c.transport.recv(int(h.fragLen) - HeaderLen)
  result = header & rest

proc connect*(t: Transport; interfaceUuid: Uuid; interfaceVersion: uint32;
              transferSyntax: SyntaxId = ndrTransferSyntax();
              maxXmit: uint16 = 5840; maxRecv: uint16 = 5840;
              auth: AuthProvider = nil;
              authLevel: AuthnLevel = alPktPrivacy;
              targetSpn: string = ""): RpcClient =
  ## Connect, BIND (with optional NTLM auth handshake), and return a
  ## ready-to-use client.
  result = RpcClient(
    transport: t,
    interfaceUuid: interfaceUuid,
    interfaceVersion: interfaceVersion,
    transferSyntax: transferSyntax,
    contextId: 0,
    callId: 1,
    maxXmit: maxXmit, maxRecv: maxRecv,
    auth: auth, authLevel: authLevel,
    authContextId: 0)

  let bp = BindPdu(
    maxXmit: maxXmit, maxRecv: maxRecv, assocGroupId: 0,
    contexts: @[PresentationContext(
      contextId: 0,
      abstractSyntax: SyntaxId(uuid: interfaceUuid, version: interfaceVersion),
      transferSyntaxes: @[transferSyntax])])
  let cid = result.nextCallId()

  if auth == nil:
    t.send(buildBind(cid, bp, maxXmit, maxRecv))
  else:
    let token = auth.initialize(targetSpn)
    t.send(wrapBindWithAuth(cid, bp, result.authContextId, token, authLevel))

  let ackPdu = result.readPdu()
  let pb = newBuffer(ackPdu)
  let h = pb.readHeader()
  if h.pType == ptBindNak:
    raise newException(RpcClientError, "server rejected BIND")
  if h.pType != ptBindAck:
    raise newException(RpcClientError, "unexpected PDU type " & $h.pType)
  let ack = pb.parseBindAckBody()
  if ack.results.len == 0:
    raise newException(RpcClientError, "BIND_ACK has no context results")
  if ack.results[0].result != pcAcceptance:
    raise newException(RpcClientError, "context 0 not accepted")
  result.maxXmit = min(maxXmit, ack.maxXmit)
  result.maxRecv = min(maxRecv, ack.maxRecv)

  if auth != nil:
    let (_, _, verifier) = parseAuthVerifier(ackPdu)
    if verifier.len == 0:
      raise newException(RpcClientError, "BIND_ACK missing CHALLENGE token")
    let authToken = auth.step(verifier)
    let auth3Pdu = buildAuth3(result.nextCallId(), result.authContextId,
                              authToken, authLevel)
    t.send(auth3Pdu)
    # AUTH3 has no reply, but we MUST flush it to the wire before the
    # first REQUEST: on named-pipe transports two PDUs in one
    # FSCTL_PIPE_TRANSCEIVE causes Windows to close the pipe.
    t.flush()

proc buildRequestPrologue(stubLen: int; contextId: uint16;
                          opnum: uint16): seq[byte] =
  ## 8-byte REQUEST prologue: alloc_hint + p_cont_id + opnum.
  result = newSeq[byte](8)
  result[0] = byte(stubLen and 0xff)
  result[1] = byte((stubLen shr 8) and 0xff)
  result[2] = byte((stubLen shr 16) and 0xff)
  result[3] = byte((stubLen shr 24) and 0xff)
  result[4] = byte(contextId and 0xff)
  result[5] = byte((contextId shr 8) and 0xff)
  result[6] = byte(opnum and 0xff)
  result[7] = byte((opnum shr 8) and 0xff)

proc maxStubBytesPerCall(c: RpcClient): int =
  ## How many stub bytes fit in one PDU.
  ##  - Unauthenticated: RequestHeaderOverhead = 16 + 8 = 24 bytes overhead.
  ##  - Authenticated: add 8 (sec_trailer) + 16 (NTLM verifier) + worst-case
  ##    3 bytes of padding.
  result = int(c.maxXmit) - RequestHeaderOverhead
  if c.auth != nil:
    result -= SecTrailerLen + c.auth.maxSigSize + 3   # pad allowance

proc sendOneRequestPdu(c: RpcClient; cid: uint32; opnum: uint16;
                       chunk: openArray[byte]; flags: PfcFlags) =
  if c.auth == nil:
    let req = RequestPdu(callId: cid, contextId: c.contextId,
                         opnum: opnum, stub: @chunk)
    c.transport.send(req.buildRequest(flags))
  else:
    var hdr = defaultHeader(ptRequest, cid, flags)
    let prologue = buildRequestPrologue(chunk.len, c.contextId, opnum)
    let wrapped = wrapOutgoing(hdr, chunk, c.auth, c.authLevel,
                                c.authContextId, prologue)
    c.transport.send(wrapped)

proc call*(c: RpcClient; opnum: uint16; stub: openArray[byte]): seq[byte] =
  ## Issue a REQUEST (possibly fragmented) and return the reassembled
  ## response stub. Auth-wrapping and seq#-incrementing happen per
  ## fragment.
  let cid = c.nextCallId()

  # Fragment outbound stub.
  let chunkSize = c.maxStubBytesPerCall
  doAssert chunkSize > 0, "maxXmit too small for any payload"
  if stub.len <= chunkSize:
    c.sendOneRequestPdu(cid, opnum, stub,
                         {pfcFirstFrag, pfcLastFrag})
  else:
    var off = 0
    var first = true
    while off < stub.len:
      let take = min(chunkSize, stub.len - off)
      let isLast = off + take == stub.len
      var flags: PfcFlags
      if first: flags.incl pfcFirstFrag
      if isLast: flags.incl pfcLastFrag
      c.sendOneRequestPdu(cid, opnum,
                           toOpenArray(stub, off, off + take - 1),
                           flags)
      off += take
      first = false

  # Reassemble inbound PDUs.
  result = @[]
  while true:
    let p = c.readPdu()
    let b = newBuffer(p)
    let h = b.readHeader()
    if h.callId != cid:
      raise newException(RpcClientError, "callId mismatch")
    case h.pType
    of ptResponse:
      var chunk: seq[byte]
      if c.auth == nil:
        chunk = parseResponse(p).stub
      else:
        let (s, ok) = unwrapIncoming(p, c.auth, prologueLen = 8)
        if not ok:
          raise newException(RpcClientError, "auth verification failed")
        chunk = s
      result.add chunk
      if pfcLastFrag in h.flags: break
    of ptFault:
      let f = parseFault(p)
      raise newException(RpcClientError, "RPC fault: 0x" & $f.status)
    else:
      raise newException(RpcClientError, "unexpected PDU " & $h.pType)

proc close*(c: RpcClient) =
  if c.transport != nil:
    c.transport.close()
    c.transport = nil
