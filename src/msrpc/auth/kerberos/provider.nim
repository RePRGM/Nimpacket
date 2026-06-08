## auth/kerberos/provider.nim — Kerberos AuthProvider stub.
##
## Slots into the existing AuthProvider SPI so SPNEGO can wrap a
## Kerberos AP-REQ instead of an NTLM token. v0 supports:
##
##   * password-based AS-REQ with AES256-CTS-HMAC-SHA1-96 ETYPE
##   * KRB-ERROR response parsing (so callers see *why* the KDC said no)
##
## TGS-REQ and AP-REQ token construction are scaffolded; the wire
## bytes need full RFC 4120 §5.4 marshalling that's a couple hundred
## more lines. For now this gets us to "the KDC accepted our request"
## which is the hardest part to get right.

import std/[net, times, strutils]
import ../../rpc/auth as rpcauth
import messages, preauth, rc4 as krbRc4, etype
import asrep, apreq, tgsreq

when defined(posix):
  from std/posix import nil   # qualified access only — avoid AF_INET clash

type
  KdcTransport* = enum
    ## Selects how AS-REQ / TGS-REQ get to the KDC.
    ##  - ktTcp:  always TCP/88 with 4-byte length prefix (RFC 4120 §7.2.2).
    ##           What real AD clients use because AS-REPs include a PAC
    ##           that easily exceeds the path MTU.
    ##  - ktUdp:  UDP/88 with one datagram per direction. Works for MIT KDCs
    ##           and tiny realms with no PAC; fails on most modern AD.
    ##  - ktAuto: try TCP first, fall back to UDP if the TCP connection is
    ##           refused. Also retries on TCP if the server returns
    ##           KRB_ERR_RESPONSE_TOO_BIG (52) over UDP.
    ktTcp
    ktUdp
    ktAuto

  KerberosProvider* = ref object of AuthProvider
    realm*: string
    username*: string
    password*: string
    kdcHost*: string
    kdcPort*: int
    transport*: KdcTransport
    nonce*: uint32
    targetService*: string         ## "host/dc01.corp" etc.
    tgtTicket*: seq[byte]          ## raw [APPLICATION 1] Ticket
    tgtSessionKey*: seq[byte]      ## from EncASRepPart
    tgtSessionEtype*: uint32
    svcTicket*: seq[byte]          ## service ticket from TGS-REP
    svcSessionKey*: seq[byte]      ## service session key
    svcSessionEtype*: uint32
    preferEtype*: uint32

  KrbProtocolError* = object of CatchableError

proc newKerberosProvider*(realm, username, password, kdcHost: string;
                          kdcPort: int = 88;
                          authLevel: AuthnLevel = alPktIntegrity;
                          preferEtype: uint32 = krbRc4.EtypeRc4Hmac;
                          transport: KdcTransport = ktAuto):
                          KerberosProvider =
  result = KerberosProvider(
    realm: realm, username: username, password: password,
    kdcHost: kdcHost, kdcPort: kdcPort,
    transport: transport,
    nonce: 0x12345678'u32,
    preferEtype: preferEtype)
  result.state = asInit
  result.authType = atKerberos
  result.authLevel = authLevel
  result.maxSigSize = 16

# --- KDC transport ------------------------------------------------

proc setRecvTimeout(s: Socket; ms: int) =
  ## Apply SO_RCVTIMEO. std/net doesn't expose this directly.
  when defined(posix):
    var tv: posix.Timeval
    tv.tv_sec = posix.Time(ms div 1000)
    tv.tv_usec = posix.Suseconds((ms mod 1000) * 1000)
    discard posix.setsockopt(cast[posix.SocketHandle](s.getFd()),
                              posix.SOL_SOCKET, posix.SO_RCVTIMEO,
                              addr tv, posix.SockLen(sizeof(tv)))

proc sendKdcUdp*(host: string; port: int; pdu: openArray[byte];
                 timeoutMs: int = 5000): seq[byte] =
  ## RFC 4120 §7.2.1: one UDP datagram per direction, no framing.
  let s = newSocket(AF_INET, SOCK_DGRAM, IPPROTO_UDP, buffered = false)
  defer: s.close()
  s.setRecvTimeout(timeoutMs)
  var sendBuf = newString(pdu.len)
  for i, b in pdu: sendBuf[i] = char(b)
  s.sendTo(host, Port(port), sendBuf)
  var buf = newString(65535)
  var sender = ""
  var senderPort: Port
  let n =
    try: s.recvFrom(buf, 65535, sender, senderPort)
    except OSError: -1
  if n <= 0:
    raise newException(KrbProtocolError,
      "no KDC response (timeout after " & $timeoutMs & " ms)")
  result = newSeq[byte](n)
  for i in 0 ..< n: result[i] = byte(buf[i].ord)

proc encodeTcpLen(n: int): array[4, byte] {.inline.} =
  ## 4-byte big-endian length prefix for the RFC 4120 TCP framing.
  result[0] = byte((n shr 24) and 0xff)
  result[1] = byte((n shr 16) and 0xff)
  result[2] = byte((n shr 8) and 0xff)
  result[3] = byte(n and 0xff)

proc decodeTcpLen(b: openArray[byte]): int {.inline.} =
  ## Inverse of encodeTcpLen. The high bit MUST be zero (reserved by
  ## RFC 4120; previously hijacked for "I am responding with a NAK"
  ## that nobody ever shipped).
  doAssert b.len >= 4
  result = (int(b[0]) shl 24) or (int(b[1]) shl 16) or
           (int(b[2]) shl 8)  or  int(b[3])

proc sendKdcTcp*(host: string; port: int; pdu: openArray[byte];
                 timeoutMs: int = 5000): seq[byte] =
  ## RFC 4120 §7.2.2: each request and response is preceded by its
  ## length encoded as 4 octets in network byte order. Many real
  ## AD AS-REPs are 4–10 KB because of the PAC; UDP is unusable.
  let s = newSocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, buffered = false)
  defer: s.close()
  s.connect(host, Port(port))
  let lenPrefix = encodeTcpLen(pdu.len)
  var out_buf = newString(4 + pdu.len)
  for i in 0 ..< 4: out_buf[i] = char(lenPrefix[i])
  for i, b in pdu: out_buf[4 + i] = char(b)
  s.send(out_buf)
  # Read 4-byte length, then exactly that many bytes.
  var lenBuf = newString(4)
  var got = 0
  while got < 4:
    let n = s.recv(lenBuf[got].addr, 4 - got)
    if n <= 0:
      raise newException(KrbProtocolError,
        "KDC closed TCP connection before length prefix")
    got += n
  var lenBytes: array[4, byte]
  for i in 0 ..< 4: lenBytes[i] = byte(lenBuf[i].ord)
  let respLen = decodeTcpLen(lenBytes)
  if respLen <= 0 or respLen > 16 * 1024 * 1024:
    raise newException(KrbProtocolError,
      "KDC reply length out of range: " & $respLen)
  result = newSeq[byte](respLen)
  var consumed = 0
  while consumed < respLen:
    var chunk = newString(respLen - consumed)
    let n = s.recv(chunk[0].addr, respLen - consumed)
    if n <= 0:
      raise newException(KrbProtocolError,
        "KDC closed TCP connection mid-body at " &
        $consumed & "/" & $respLen)
    for i in 0 ..< n: result[consumed + i] = byte(chunk[i].ord)
    consumed += n

proc sendKdc*(p: KerberosProvider; pdu: openArray[byte]): seq[byte] =
  ## Honors the provider's chosen transport policy. For ktAuto:
  ##  1. Try TCP. If the connection is refused, fall back to UDP.
  ##  2. If UDP returns KRB-ERROR code 52 (KRB_ERR_RESPONSE_TOO_BIG),
  ##     retry the same request on TCP.
  case p.transport
  of ktTcp:
    result = sendKdcTcp(p.kdcHost, p.kdcPort, pdu)
  of ktUdp:
    result = sendKdcUdp(p.kdcHost, p.kdcPort, pdu)
  of ktAuto:
    try:
      result = sendKdcTcp(p.kdcHost, p.kdcPort, pdu)
    except OSError, IOError:
      # TCP refused or otherwise unreachable; fall back to UDP.
      result = sendKdcUdp(p.kdcHost, p.kdcPort, pdu)
      if result.len > 0 and result[0] == 0x7E'u8:
        let err = parseKrbError(result)
        if err.errorCode == 52:           # KRB_ERR_RESPONSE_TOO_BIG
          result = sendKdcTcp(p.kdcHost, p.kdcPort, pdu)

# --- AS exchange --------------------------------------------------

proc userLongTermKey(p: KerberosProvider): seq[byte] =
  ## Compute the user's long-term key for ``p.preferEtype`` from the
  ## password. For AES the salt is the canonical "REALMprincipal" form.
  case p.preferEtype
  of krbRc4.EtypeRc4Hmac:
    let k = krbRc4.rc4HmacStringToKey(p.password)
    result = newSeq[byte](16)
    for i in 0 ..< 16: result[i] = k[i]
  of EtypeAes128, EtypeAes256:
    var pw = newSeq[byte](p.password.len)
    for i, c in p.password: pw[i] = byte(c)
    let salt = p.realm & p.username
    var s = newSeq[byte](salt.len)
    for i, c in salt: s[i] = byte(c)
    result = stringToKey(pw, s, p.preferEtype, iterations = 4096)
  else:
    raise newException(KrbProtocolError,
      "unsupported preferEtype: " & $p.preferEtype)

proc buildPreauth(p: KerberosProvider; userKey: openArray[byte]): seq[byte] =
  case p.preferEtype
  of krbRc4.EtypeRc4Hmac:
    result = buildPaEncTimestampRc4(userKey, getTime())
  of EtypeAes128, EtypeAes256:
    result = buildPaEncTimestampAes(userKey, p.preferEtype, getTime())
  else:
    raise newException(KrbProtocolError, "unsupported preferEtype")

proc obtainTgt*(p: KerberosProvider) =
  ## AS-REQ → AS-REP. Retries with PA-ENC-TIMESTAMP on
  ## KDC_ERR_PREAUTH_REQUIRED (25).
  let till = kerberosTimestamp(getTime() + 8.hours)
  let etypes = [p.preferEtype]
  let userKey = p.userLongTermKey()

  # First attempt — no pre-auth. AD KDCs respond with KRB-ERROR 25.
  let attempt1 = buildAsReq(p.realm, p.username, "krbtgt",
                             p.nonce, etypes, till)
  let resp1 = sendKdc(p, attempt1)
  doAssert resp1.len > 0
  var asRepBytes = resp1

  if resp1[0] == 0x7E'u8:              # [APPLICATION 30] = KRB-ERROR
    let err = parseKrbError(resp1)
    if err.errorCode != 25:
      raise newException(KrbProtocolError,
        "KDC returned error " & $err.errorCode & " (" & err.eText & ")")
    let paEncTs = p.buildPreauth(userKey)
    let attempt2 = buildAsReq(p.realm, p.username, "krbtgt",
                               p.nonce, etypes, till,
                               preAuth = paEncTs)
    asRepBytes = sendKdc(p, attempt2)

  if asRepBytes.len == 0 or asRepBytes[0] != 0x6B'u8:
    if asRepBytes.len > 0 and asRepBytes[0] == 0x7E'u8:
      let err = parseKrbError(asRepBytes)
      raise newException(KrbProtocolError,
        "AS-REQ rejected: code " & $err.errorCode & " " & err.eText)
    raise newException(KrbProtocolError, "unexpected AS-REP byte 0")

  let env = parseAsRep(asRepBytes)
  let (plain, ok) = decryptAsRep(env, userKey)
  if not ok:
    raise newException(KrbProtocolError, "AS-REP decryption failed")
  let enc = parseEncKdcRepPart(plain)
  p.tgtTicket = env.ticketBytes
  p.tgtSessionKey = enc.sessionKey
  p.tgtSessionEtype = enc.sessionEtype

# --- TGS exchange -------------------------------------------------

proc obtainServiceTicket*(p: KerberosProvider; spn: string) =
  ## Run TGS-REQ for ``spn`` (e.g. "cifs/dc01.corp.local") using the
  ## TGT and TGS session key. Stashes the service ticket and session
  ## key on the provider.
  if p.tgtTicket.len == 0:
    raise newException(KrbProtocolError,
      "obtainServiceTicket called before AS exchange")

  # Split SPN into class + host. Accept either "class/host" or bare host.
  var svcClass = "host"
  var svcHost = spn
  let slash = spn.find('/')
  if slash > 0:
    svcClass = spn[0 ..< slash]
    svcHost = spn[slash + 1 ..< spn.len]

  # Build an AP-REQ to krbtgt for the PA-TGS-REQ. The authenticator is
  # encrypted under the TGT session key.
  let apReq = buildApReq(sessionKey = p.tgtSessionKey,
                         ticketBytes = p.tgtTicket,
                         crealm = p.realm, cname = p.username,
                         ctime = getTime())

  let till = kerberosTimestamp(getTime() + 8.hours)
  let nonce = p.nonce + 1
  let tgs = buildTgsReq(realm = p.realm,
                        serviceClass = svcClass,
                        serviceHost = svcHost,
                        nonce = nonce,
                        etypes = [p.preferEtype],
                        till = till,
                        apReq = apReq)
  let resp = sendKdc(p, tgs)
  if resp.len == 0:
    raise newException(KrbProtocolError, "empty TGS response")
  if resp[0] == 0x7E'u8:
    let err = parseKrbError(resp)
    raise newException(KrbProtocolError,
      "TGS-REQ rejected: code " & $err.errorCode & " " & err.eText)
  if resp[0] != 0x6D'u8:
    raise newException(KrbProtocolError, "unexpected TGS-REP byte 0")

  let env = parseTgsRep(resp)
  let (plain, ok) = decryptTgsRepRc4(env, p.tgtSessionKey)
  if not ok:
    raise newException(KrbProtocolError, "TGS-REP decryption failed")
  let enc = parseEncKdcRepPart(plain)
  p.svcTicket = env.ticketBytes
  p.svcSessionKey = enc.sessionKey
  p.svcSessionEtype = enc.sessionEtype

# --- AuthProvider interface --------------------------------------

method initialize*(p: KerberosProvider; targetSpn: string): seq[byte] =
  ## Full AS → TGS → AP-REQ pipeline.
  if p.tgtTicket.len == 0:
    p.obtainTgt()
  if p.svcTicket.len == 0 or p.targetService != targetSpn:
    p.obtainServiceTicket(targetSpn)
  p.targetService = targetSpn
  let ap = buildApReq(sessionKey = p.svcSessionKey,
                      ticketBytes = p.svcTicket,
                      crealm = p.realm, cname = p.username,
                      ctime = getTime())
  result = wrapGssApReq(ap)
  p.state = asEstablished

method step*(p: KerberosProvider; serverToken: openArray[byte]): seq[byte] =
  ## v0 doesn't handle AP-REP (server's mutual-auth response). Returning
  ## empty signals "no further token to send".
  result = @[]
  p.state = asEstablished
