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

type
  KerberosProvider* = ref object of AuthProvider
    realm*: string
    username*: string
    password*: string
    kdcHost*: string
    kdcPort*: int
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
                          preferEtype: uint32 = krbRc4.EtypeRc4Hmac):
                          KerberosProvider =
  result = KerberosProvider(
    realm: realm, username: username, password: password,
    kdcHost: kdcHost, kdcPort: kdcPort,
    nonce: 0x12345678'u32,
    preferEtype: preferEtype)
  result.state = asInit
  result.authType = atKerberos
  result.authLevel = authLevel
  result.maxSigSize = 16

# --- KDC transport ------------------------------------------------

proc sendKdcUdp*(host: string; port: int; pdu: openArray[byte];
                 timeoutMs: int = 5000): seq[byte] =
  ## Send a KRB5 request over UDP and read one datagram back.
  ## TCP transport is also defined by RFC 4120 (4-byte length-prefix);
  ## we'd add it once we hit AS-REP messages > 1500 bytes.
  let s = newSocket(AF_INET, SOCK_DGRAM, IPPROTO_UDP, buffered = false)
  defer: s.close()
  var sendBuf = newString(pdu.len)
  for i, b in pdu: sendBuf[i] = char(b)
  s.sendTo(host, Port(port), sendBuf)
  var buf = newString(65535)
  var sender = ""
  var senderPort: Port
  let n = s.recvFrom(buf, 65535, sender, senderPort)
  if n <= 0:
    raise newException(KrbProtocolError, "no KDC response")
  result = newSeq[byte](n)
  for i in 0 ..< n: result[i] = byte(buf[i].ord)

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
  let resp1 = sendKdcUdp(p.kdcHost, p.kdcPort, attempt1)
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
    asRepBytes = sendKdcUdp(p.kdcHost, p.kdcPort, attempt2)

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
  let resp = sendKdcUdp(p.kdcHost, p.kdcPort, tgs)
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
