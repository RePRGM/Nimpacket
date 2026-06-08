## rpc/wrapper.nim — wrap an outbound PDU body with sec_trailer + auth
## verifier, and unwrap the inverse on inbound.
##
## Layout of an authenticated PDU (after the 16-byte header)::
##
##   stub_data        (caller-supplied)
##   auth_padding     (zeros, to align stub end to 4-byte boundary)
##   sec_trailer      (8 bytes)
##   auth_verifier    (auth_length bytes; 16 for NTLM ESS)
##
## When the auth level is privacy: stub_data + auth_padding are
## RC4-encrypted (NTLM) under the sealing key; sec_trailer is in
## plaintext; the verifier is the signed-and-RC4'd HMAC.
##
## When the auth level is integrity: nothing is encrypted, but the
## verifier still covers stub + pad + sec_trailer.

import ../common/[buffers, endian]
import ../auth/ntlm/[provider, session]
import pdu, auth, binds

const AuthAlignment* = 4

proc padToAlign*(data: var seq[byte]; alignment: int) =
  let extra = data.len mod alignment
  if extra != 0:
    let pad = alignment - extra
    for _ in 0 ..< pad: data.add 0'u8

proc wrapOutgoing*(header: PduHeader;
                   stub: openArray[byte];
                   provider: NtlmProvider;
                   level: AuthnLevel;
                   contextId: uint32;
                   typeSpecificPrologue: openArray[byte]): seq[byte] =
  ## Build a complete PDU including header, type-specific prologue
  ## (e.g. alloc_hint + p_cont_id + opnum for REQUEST), stub_data,
  ## auth_padding, sec_trailer, and verifier.
  ##
  ## ``provider`` must already have its session keys established.
  ## ``level`` must be ``alPktIntegrity`` or ``alPktPrivacy``.
  var pre = newSeq[byte](typeSpecificPrologue.len)
  for i, b in typeSpecificPrologue: pre[i] = b

  # Bytes to be authenticated = prologue + stub + pad + sec_trailer.
  # (Pad aligns the END of the stub data to AuthAlignment, measured
  # from the start of the PDU body — but since the body always begins
  # right after the 16-byte header, it's equivalent to align the byte
  # offset of the trailer to AuthAlignment.)
  var body = pre & @stub
  padToAlign(body, AuthAlignment)
  let padLen = body.len - pre.len - stub.len

  # Build sec_trailer
  let trailer = SecTrailer(
    authType: atNtlm, authLevel: level,
    padLength: uint8(padLen), reserved: 0,
    contextId: contextId)
  let tb = newBuffer()
  tb.writeSecTrailer(trailer)
  let trailerBytes = tb.consumed
  body.add trailerBytes

  # Sign or sign+seal. The "sealLen" prefix is everything except the
  # 8 trailer bytes at the end.
  let sealLen = body.len - trailerBytes.len
  var verifier: seq[byte]
  case level
  of alPktIntegrity:
    # Sign over (prologue + stub + pad + trailer); no encryption.
    let sig = provider.session.signSealPartial(body, sealLen = 0,
                                                forClient = true)
    verifier = newSeq[byte](16)
    for i in 0 ..< 16: verifier[i] = sig[i]
  of alPktPrivacy:
    let sig = provider.rpcSignSeal(body, sealLen)
    verifier = sig
  else:
    raise newException(ValueError, "wrapOutgoing requires integrity or privacy")

  # Assemble header with correct lengths.
  var hdr = header
  hdr.authLen = uint16(verifier.len)
  hdr.fragLen = uint16(HeaderLen + body.len + verifier.len)

  let out_buf = newBuffer()
  out_buf.writeHeader(hdr)
  out_buf.writeBytes(body)
  out_buf.writeBytes(verifier)
  result = out_buf.consumed

# --- BIND with auth -----------------------------------------------------

proc wrapBindWithAuth*(callId: uint32; bp: BindPdu;
                       contextId: uint32;
                       authToken: openArray[byte];
                       level: AuthnLevel = alPktPrivacy;
                       authType = atNtlm): seq[byte] =
  ## Build a BIND PDU whose auth_verifier carries an NTLM Type-1 token.
  ## The BIND body itself is unencrypted; only the auth_verifier is
  ## appended after a sec_trailer.
  ##
  ## auth_length on the wire counts only the verifier bytes, not the
  ## 8-byte sec_trailer (per MS-RPCE §2.2.2.11).
  let body = buildBindBody(bp)
  let st = SecTrailer(authType: authType, authLevel: level,
                      padLength: 0, reserved: 0, contextId: contextId)
  let tb = newBuffer()
  tb.writeSecTrailer(st)
  var hdr = defaultHeader(ptBind, callId)
  hdr.fragLen = uint16(HeaderLen + body.len + SecTrailerLen + authToken.len)
  hdr.authLen = uint16(authToken.len)

  let b = newBuffer()
  b.writeHeader(hdr)
  b.writeBytes(body)
  b.writeBytes(tb.consumed)
  b.writeBytes(authToken)
  result = b.consumed

proc parseAuthVerifier*(pduBytes: openArray[byte]):
    tuple[bodyEnd: int; trailer: SecTrailer; verifier: seq[byte]] =
  ## Pull the sec_trailer + verifier off the tail of any PDU that
  ## carries auth. ``bodyEnd`` is the byte offset where the PDU body
  ## (and any padding) ends, before the sec_trailer.
  let b = newBuffer(@pduBytes)
  let hdr = b.readHeader()
  if hdr.authLen == 0:
    return (bodyEnd: int(hdr.fragLen), trailer: SecTrailer(), verifier: @[])
  let verifierStart = int(hdr.fragLen) - int(hdr.authLen)
  let trailerStart = verifierStart - SecTrailerLen
  result.bodyEnd = trailerStart
  let tb = newBuffer(@pduBytes[trailerStart ..< verifierStart])
  result.trailer = tb.readSecTrailer()
  result.verifier = @pduBytes[verifierStart ..< int(hdr.fragLen)]

# --- AUTH3 PDU ----------------------------------------------------------

proc buildAuth3*(callId: uint32; contextId: uint32;
                 authToken: openArray[byte];
                 level: AuthnLevel = alPktPrivacy;
                 authType = atNtlm): seq[byte] =
  ## Per MS-RPCE §2.2.2.10 the AUTH3 PDU body is a 4-byte ``MaxXmitFrag``
  ## (reserved, MUST be ignored) followed by the sec_trailer + verifier.
  let st = SecTrailer(authType: authType, authLevel: level,
                      padLength: 0, reserved: 0, contextId: contextId)
  let tb = newBuffer()
  tb.writeSecTrailer(st)
  var hdr = defaultHeader(ptAuth3, callId)
  hdr.fragLen = uint16(HeaderLen + 4 + SecTrailerLen + authToken.len)
  hdr.authLen = uint16(authToken.len)

  let b = newBuffer()
  b.writeHeader(hdr)
  b.writeU32LE(0)               # reserved 4 bytes
  b.writeBytes(tb.consumed)
  b.writeBytes(authToken)
  result = b.consumed

proc unwrapIncoming*(pdu_bytes: openArray[byte];
                      provider: NtlmProvider;
                      prologueLen: int): tuple[stub: seq[byte]; ok: bool] =
  ## Decode an authenticated inbound PDU. ``prologueLen`` is the
  ## type-specific prologue size (8 for RESPONSE: alloc_hint + p_cont_id
  ## + cancel_count + reserved).
  let buf = newBuffer(@pdu_bytes)
  let hdr = buf.readHeader()
  if hdr.authLen == 0:
    # Unauthenticated reply; whole body after prologue is stub.
    let bodyLen = int(hdr.fragLen) - HeaderLen
    discard buf.readBytes(prologueLen)
    return (stub: buf.readBytes(bodyLen - prologueLen), ok: true)

  let bodyLen = int(hdr.fragLen) - HeaderLen - int(hdr.authLen)
  var body = buf.readBytes(bodyLen)
  let verifier = buf.readBytes(int(hdr.authLen))
  # body = prologue || stub_encrypted || pad || sec_trailer
  if body.len < prologueLen + SecTrailerLen:
    return (stub: @[], ok: false)
  let trailerOffset = body.len - SecTrailerLen
  let trailerBuf = newBuffer(body[trailerOffset ..< body.len])
  let st = trailerBuf.readSecTrailer()

  # Decrypt + verify.
  let sealLen = trailerOffset
  if not provider.rpcUnsealVerify(body, sealLen, verifier):
    return (stub: @[], ok: false)

  # Strip prologue, padding, and sec_trailer to recover the stub.
  let padLen = int(st.padLength)
  let stubLen = trailerOffset - prologueLen - padLen
  if stubLen < 0:
    return (stub: @[], ok: false)
  result.stub = body[prologueLen ..< prologueLen + stubLen]
  result.ok = true
