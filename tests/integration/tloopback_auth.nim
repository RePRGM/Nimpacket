## Tier B: end-to-end authenticated round-trip over TCP.
##
## A mock RPC server in a background thread performs a full NTLMv2
## handshake (using the same library, mirroring credentials), then
## echoes one signed+sealed REQUEST through a signed+sealed RESPONSE.
##
## This is the most ambitious test in the suite: every layer (TCP,
## PDU framing, BIND/AUTH3, NTLM messages, NTOWFv2, session keys,
## sign/seal, sec_trailer placement, NDR-less stub passthrough) is
## exercised on real bytes between two distinct sessions.

import std/[unittest, net, os, nativesockets, typedthreads]
import msrpc/common/[buffers, endian, guid]
import msrpc/auth/ntlm/[ntowf, messages, session, provider]
import msrpc/crypto/rc4
import msrpc/rpc/[pdu, binds, auth, wrapper, transport_tcp, client]

const TestPort = 24819
const Domain = "DOMAIN"
const User = "alice"
const Password = "P@ssw0rd!"
const Workstation = "CLI"

# --- mock server helpers ----------------------------------------------

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

proc serveAuth(port: int) {.thread.} =
  ## Mock RPC server that does one full NTLM-authenticated call.
  let listener = newSocket()
  listener.setSockOpt(OptReuseAddr, true)
  listener.bindAddr(Port(port))
  listener.listen(1)
  var conn: Socket
  listener.accept(conn)
  listener.close()

  # --- 1. Read BIND with auth ---
  let bindBytes = recvPdu(conn)
  let bb = newBuffer(bindBytes)
  let bindHdr = bb.readHeader()
  doAssert bindHdr.pType == ptBind
  let bp = bb.parseBindBody()
  let (_, _, clientNeg) = parseAuthVerifier(bindBytes)
  doAssert clientNeg.len > 0
  discard parseNegotiate(clientNeg)   # validate it's a NEGOTIATE

  # --- 2. Send BIND_ACK with CHALLENGE ---
  let serverChallenge: array[8, byte] =
    [0x01'u8, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]
  let targetInfo = serialize(@[
    AvPair(id: MsvAvNbDomain,   value: @[byte('D'), 0, byte('O'), 0, byte('M'), 0]),
    AvPair(id: MsvAvNbComputer, value: @[byte('S'), 0, byte('R'), 0, byte('V'), 0])])
  let challenge = ChallengeMessage(
    flags: {NEGOTIATE_UNICODE, NEGOTIATE_NTLM,
            NEGOTIATE_EXTENDED_SESSIONSECURITY, NEGOTIATE_TARGET_INFO,
            NEGOTIATE_KEY_EXCH, NEGOTIATE_128, NEGOTIATE_SEAL,
            NEGOTIATE_SIGN, NEGOTIATE_ALWAYS_SIGN, TARGET_TYPE_SERVER},
    targetName: "DOMAIN",
    serverChallenge: serverChallenge,
    targetInfo: targetInfo,
    hasVersion: false).build()

  let ackBody = BindAckPdu(
    maxXmit: bp.maxXmit, maxRecv: bp.maxRecv, assocGroupId: 0x42,
    secondaryAddress: "",
    results: @[PContextResultEntry(
      result: pcAcceptance, reason: 0,
      transferSyntax: bp.contexts[0].transferSyntaxes[0])])
  # Embed the CHALLENGE as auth verifier of BIND_ACK.
  let body = buildBindAckBody(ackBody)
  let st = SecTrailer(authType: atNtlm, authLevel: alPktPrivacy,
                      padLength: 0, reserved: 0, contextId: 0)
  let tb = newBuffer()
  tb.writeSecTrailer(st)
  var ackHdr = defaultHeader(ptBindAck, bindHdr.callId)
  ackHdr.fragLen = uint16(HeaderLen + body.len + SecTrailerLen + challenge.len)
  ackHdr.authLen = uint16(challenge.len)
  let outBuf = newBuffer()
  outBuf.writeHeader(ackHdr)
  outBuf.writeBytes(body)
  outBuf.writeBytes(tb.consumed)
  outBuf.writeBytes(challenge)
  sendAll(conn, outBuf.consumed)

  # --- 3. Read AUTH3 with AUTHENTICATE ---
  let auth3Bytes = recvPdu(conn)
  let (_, _, authVerifier) = parseAuthVerifier(auth3Bytes)
  doAssert authVerifier.len > 0
  let am = parseAuthenticate(authVerifier)
  doAssert am.user == User
  doAssert am.domain == Domain

  # --- 4. Derive the SAME session keys the client did ---
  let nk = ntowfV2(Password, User, Domain)
  let rsk = rc4(nk, am.encryptedRandomSessionKey)   # decrypt ExportedSessionKey
  # Wait: the client encrypts ExportedSessionKey under KeyExchangeKey.
  # KeyExchangeKey = SessionBaseKey for NTLMv2. We don't have the client
  # challenge here — the spec says the server recomputes it from the
  # NtChallengeResponse, but we cheat: pull it out of the NTLMv2
  # response, which carries it inside ``temp``.
  # NTLMv2 response layout: NTProofStr(16) || Responserversion(1) ||
  # HiResponserversion(1) || Z(6) || Timestamp(8) || ClientChallenge(8) || ...
  doAssert am.ntResponse.len >= 16 + 8 + 8 + 8
  var clientChal: array[8, byte]
  for i in 0 ..< 8:
    clientChal[i] = am.ntResponse[16 + 8 + 8 + i]
  let timestamp = uint64(
    am.ntResponse[16 + 8 + 0]) or
    (uint64(am.ntResponse[16 + 8 + 1]) shl 8) or
    (uint64(am.ntResponse[16 + 8 + 2]) shl 16) or
    (uint64(am.ntResponse[16 + 8 + 3]) shl 24) or
    (uint64(am.ntResponse[16 + 8 + 4]) shl 32) or
    (uint64(am.ntResponse[16 + 8 + 5]) shl 40) or
    (uint64(am.ntResponse[16 + 8 + 6]) shl 48) or
    (uint64(am.ntResponse[16 + 8 + 7]) shl 56)
  # Reconstruct TargetInfo from temp (everything after offsets above,
  # excluding the trailing Z(4)).
  let tiStart = 16 + 8 + 8 + 8 + 4
  let tiEnd = am.ntResponse.len - 4
  let serverTargetInfo = am.ntResponse[tiStart ..< tiEnd]

  let ntv2 = computeNtV2Response(nk, serverChallenge, clientChal,
                                  timestamp, serverTargetInfo)
  let exportedKey = rc4(ntv2.sessionBaseKey, am.encryptedRandomSessionKey)
  discard rsk

  # The server provider derives the same four session keys; ``role``
  # ensures sign/seal and verify use the correct directions (server
  # verifies client→server, signs server→client).
  let srv = newNtlmProvider(Domain, User, Password, role = nrServer)
  for i in 0 ..< 16: srv.exportedSessionKey[i] = exportedKey[i]
  srv.session = newNtlmSession(srv.exportedSessionKey)

  # --- 5. Read sealed REQUEST and decrypt+verify ---
  let reqBytes = recvPdu(conn)
  let (stub, ok) = unwrapIncoming(reqBytes, srv, prologueLen = 8)
  doAssert ok, "server failed to verify request"

  # --- 6. Build sealed RESPONSE echoing the stub back ---
  let reqHdr = newBuffer(reqBytes).readHeader()
  var respHdr = defaultHeader(ptResponse, reqHdr.callId)
  let respProl = block:
    let b = newBuffer()
    # alloc_hint(4) + p_cont_id(2) + cancel_count(1) + reserved(1)
    b.writeU32LE(uint32(stub.len))
    b.writeU16LE(0)
    b.writeByte(0); b.writeByte(0)
    b.consumed
  let respBytes = wrapOutgoing(respHdr, stub, srv,
                                level = alPktPrivacy,
                                contextId = 0,
                                typeSpecificPrologue = respProl)
  sendAll(conn, respBytes)
  conn.close()

# --- the test ---------------------------------------------------------

suite "rpc loopback authenticated (Tier B)":
  test "BIND-with-auth + AUTH3 + sealed echo call":
    var th: Thread[int]
    createThread(th, serveAuth, TestPort)
    sleep(50)

    let t = newTcpTransport("127.0.0.1", TestPort)
    let raaUuid = parseUuid("0b1c2170-5732-4e0e-8cd3-d9b16f3b84d7")
    let p = newNtlmProvider(Domain, User, Password, Workstation,
                            authLevel = alPktPrivacy)
    let c = connect(t, raaUuid, interfaceVersion = 0,
                    auth = p, authLevel = alPktPrivacy,
                    targetSpn = "host/srv")
    check c != nil
    let payload = @[0xDE'u8, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04, 0x05]
    let echoed = c.call(opnum = 1, stub = payload)
    check echoed == payload
    c.close()
    th.joinThread()
