## auth/kerberos/mockkdc.nim — in-process mock KDC for testing.
##
## Stands up a thread that listens on TCP (with the RFC 4120 §7.2.2
## length-prefix framing) and answers AS-REQ → KRB-ERROR(25) →
## PA-ENC-TIMESTAMP → AS-REP → TGS-REQ → TGS-REP. Just enough to drive
## the client provider through a complete exchange without depending
## on a real KDC.
##
## Scope: RC4-HMAC ETYPE only on the wire. The crypto operations the
## client expects (encrypt EncASRepPart under user key + usage 3, etc.)
## use the same rc4HmacEncrypt path the production client uses, so the
## round-trip exercises the real decrypt path.
##
## Out of scope: pre-authentication timestamp validation (we just trust
## that the client sent one), full ticket structure validation (the
## mock ticket bytes are opaque to the client), AES ETYPEs.

import std/[net, times]
import ../../common/buffers
import ../spnego/asn1
import messages, rc4 as krbRc4

# --- minimal KRB-ERROR builder ------------------------------------

proc buildKrbError*(realm, serviceName: string; errorCode: int;
                    stime: Time = getTime()): seq[byte] =
  let inner = newBuffer()
  inner.writeBytes(fieldTag(0, derTLV(0x02'u8, @[5'u8])))               # pvno = 5
  inner.writeBytes(fieldTag(1, derTLV(0x02'u8,
                                       @[byte(appKrbError)])))          # msg-type = 30
  inner.writeBytes(fieldTag(4,
    derTLV(0x18'u8, cast[seq[byte]](kerberosTimestamp(stime)))))        # stime
  inner.writeBytes(fieldTag(5, derTLV(0x02'u8, @[0'u8])))               # susec
  var errBytes: seq[byte] = @[]
  var v = errorCode
  if v < 0:
    errBytes.add 0'u8                                                   # we don't go negative
  else:
    while v > 0:
      errBytes.insert(byte(v and 0xff), 0)
      v = v shr 8
    if errBytes.len == 0: errBytes = @[0'u8]
    if (errBytes[0] and 0x80) != 0: errBytes.insert(0'u8, 0)
  inner.writeBytes(fieldTag(6, derTLV(0x02'u8, errBytes)))              # error-code
  inner.writeBytes(fieldTag(9, derTLV(0x1B'u8, cast[seq[byte]](realm))))
  inner.writeBytes(fieldTag(10, principalName(NtSrvInst,
                                                [serviceName, realm])))
  result = derTLV(appConstructed(appKrbError),
                   derTLV(tagSequence, inner.consumed))

# --- minimal Ticket -----------------------------------------------

proc buildTicket*(realm, serviceName: string; etype: uint32;
                  ciphertext: openArray[byte]): seq[byte] =
  ## [APPLICATION 1] Ticket ::= SEQUENCE {
  ##   tkt-vno  [0] INTEGER (5),
  ##   realm    [1] Realm,
  ##   sname    [2] PrincipalName,
  ##   enc-part [3] EncryptedData }
  let inner = newBuffer()
  inner.writeBytes(fieldTag(0, derTLV(0x02'u8, @[5'u8])))
  inner.writeBytes(fieldTag(1, derTLV(0x1B'u8, cast[seq[byte]](realm))))
  inner.writeBytes(fieldTag(2, principalName(NtSrvInst,
                                              [serviceName, realm])))
  # enc-part: SEQUENCE { etype, cipher }
  let encInner = newBuffer()
  var etBytes: seq[byte] = @[]
  var v = etype
  while v > 0:
    etBytes.insert(byte(v and 0xff), 0)
    v = v shr 8
  if etBytes.len == 0: etBytes = @[0'u8]
  if (etBytes[0] and 0x80) != 0: etBytes.insert(0'u8, 0)
  encInner.writeBytes(fieldTag(0, derTLV(0x02'u8, etBytes)))
  encInner.writeBytes(fieldTag(2, derTLV(tagOctetString, ciphertext)))
  let encPart = derTLV(tagSequence, encInner.consumed)
  inner.writeBytes(fieldTag(3, encPart))
  result = derTLV(appConstructed(appTicket),
                   derTLV(tagSequence, inner.consumed))

# --- minimal EncryptionKey [0] EncryptionKey block ----------------

proc buildEncryptionKey(etype: uint32; key: openArray[byte]): seq[byte] =
  let inner = newBuffer()
  var etBytes: seq[byte] = @[]
  var v = etype
  while v > 0:
    etBytes.insert(byte(v and 0xff), 0)
    v = v shr 8
  if etBytes.len == 0: etBytes = @[0'u8]
  if (etBytes[0] and 0x80) != 0: etBytes.insert(0'u8, 0)
  inner.writeBytes(fieldTag(0, derTLV(0x02'u8, etBytes)))
  inner.writeBytes(fieldTag(1, derTLV(tagOctetString, key)))
  result = derTLV(tagSequence, inner.consumed)

# --- minimal EncASRepPart / EncTGSRepPart -------------------------

proc buildEncKdcRepPart*(sessionEtype: uint32;
                         sessionKey: openArray[byte];
                         asRep: bool): seq[byte] =
  ## [APPLICATION 25] (AS-REP) or [APPLICATION 26] (TGS-REP) wrapping
  ## EncKDCRepPart ::= SEQUENCE { key [0], last-req [1], nonce [2],
  ##   ..., authtime, ..., realm, sname }
  ## We emit just the absolute minimum the parseEncKdcRepPart parser
  ## needs (field [0] = key).
  let inner = newBuffer()
  inner.writeBytes(fieldTag(0, buildEncryptionKey(sessionEtype, sessionKey)))
  let appTag = if asRep: 25 else: 26
  result = derTLV(appConstructed(appTag),
                   derTLV(tagSequence, inner.consumed))

# --- AS-REP / TGS-REP outer envelope ------------------------------

proc buildKdcRep*(realm, clientName, serviceName: string;
                  ticketBytes: openArray[byte];
                  encryptedKdcRepPart: openArray[byte];
                  encEtype: uint32;
                  asRep: bool): seq[byte] =
  ## [APPLICATION 11] AS-REP or [APPLICATION 13] TGS-REP wrapping
  ## SEQUENCE { pvno, msg-type, crealm, cname, ticket, enc-part }.
  let inner = newBuffer()
  inner.writeBytes(fieldTag(0, derTLV(0x02'u8, @[5'u8])))
  let mt = if asRep: 11 else: 13
  inner.writeBytes(fieldTag(1, derTLV(0x02'u8, @[byte(mt)])))
  inner.writeBytes(fieldTag(3, derTLV(0x1B'u8, cast[seq[byte]](realm))))
  inner.writeBytes(fieldTag(4, principalName(NtPrincipal, [clientName])))
  inner.writeBytes(fieldTag(5, ticketBytes))                            # raw [APPLICATION 1]
  # enc-part: SEQUENCE { etype, cipher }
  let ep = newBuffer()
  var etBytes: seq[byte] = @[]
  var v = encEtype
  while v > 0:
    etBytes.insert(byte(v and 0xff), 0)
    v = v shr 8
  if etBytes.len == 0: etBytes = @[0'u8]
  if (etBytes[0] and 0x80) != 0: etBytes.insert(0'u8, 0)
  ep.writeBytes(fieldTag(0, derTLV(0x02'u8, etBytes)))
  ep.writeBytes(fieldTag(2, derTLV(tagOctetString, encryptedKdcRepPart)))
  let encPartSeq = derTLV(tagSequence, ep.consumed)
  inner.writeBytes(fieldTag(6, encPartSeq))
  let appTag = if asRep: appAsRep else: appTgsRep
  result = derTLV(appConstructed(appTag),
                   derTLV(tagSequence, inner.consumed))

# --- the mock server itself --------------------------------------

type
  MockKdcCreds* = object
    realm*: string
    username*: string
    password*: string

  MockKdcMessageKind* = enum
    mkKrbError                       ## any KRB-ERROR seen during the run
    mkAsRep
    mkTgsRep

  MockKdcConfig* = object
    creds*: MockKdcCreds
    port*: int
    asAttempt*: int             ## how many AS-REQs we've seen
    # The mock invents these on startup and stashes them so the test
    # can assert on what was issued.
    tgtSessionKey*: array[16, byte]
    svcSessionKey*: array[16, byte]

  MockKdcResult* = object
    err*: string                     ## empty on success
    requestsServed*: int

proc fillRand(buf: var openArray[byte]) =
  let now = uint64(epochTime() * 1e6)
  var s = now
  for i in 0 ..< buf.len:
    s = s * 6364136223846793005'u64 + 1442695040888963407'u64
    buf[i] = byte((s shr 32) and 0xff'u8)

proc handleAsReq(cfg: var MockKdcConfig; reqBytes: openArray[byte]):
                 tuple[reply: seq[byte]; isError: bool] =
  ## Stateful: first AS-REQ → KRB-ERROR(25) (force pre-auth retry);
  ## subsequent AS-REQs → AS-REP with a fresh TGT session key.
  inc cfg.asAttempt
  if cfg.asAttempt == 1:
    result.reply = buildKrbError(cfg.creds.realm, "krbtgt", 25)
    result.isError = true
    return
  # Build AS-REP.
  fillRand(cfg.tgtSessionKey)
  let userKey = krbRc4.rc4HmacStringToKey(cfg.creds.password)
  let encPart = buildEncKdcRepPart(krbRc4.EtypeRc4Hmac,
                                    cfg.tgtSessionKey, asRep = true)
  # Encrypt enc-part under user's long-term key with usage 3.
  let encryptedEncPart = krbRc4.rc4HmacEncrypt(userKey, encPart, usage = 3)
  # Build a fake ticket — its body just needs to be opaque DER to the
  # client. Random bytes encrypted under a per-mock random key works.
  var ticketEncBuf: array[64, byte]
  fillRand(ticketEncBuf)
  let ticket = buildTicket(cfg.creds.realm, "krbtgt",
                            krbRc4.EtypeRc4Hmac, ticketEncBuf)
  result.reply = buildKdcRep(cfg.creds.realm, cfg.creds.username,
                              "krbtgt", ticket, encryptedEncPart,
                              krbRc4.EtypeRc4Hmac, asRep = true)
  result.isError = false

proc handleTgsReq(cfg: var MockKdcConfig; reqBytes: openArray[byte];
                  svcName, svcHost: string):
                  tuple[reply: seq[byte]; isError: bool] =
  ## Issue a service ticket with a fresh session key. Encrypt the
  ## EncTGSRepPart under the TGT session key with usage 8.
  fillRand(cfg.svcSessionKey)
  let encPart = buildEncKdcRepPart(krbRc4.EtypeRc4Hmac,
                                    cfg.svcSessionKey, asRep = false)
  let encryptedEncPart = krbRc4.rc4HmacEncrypt(cfg.tgtSessionKey,
                                                encPart, usage = 8)
  var ticketEncBuf: array[64, byte]
  fillRand(ticketEncBuf)
  let ticket = buildTicket(cfg.creds.realm, svcName,
                            krbRc4.EtypeRc4Hmac, ticketEncBuf)
  result.reply = buildKdcRep(cfg.creds.realm, cfg.creds.username,
                              svcName, ticket, encryptedEncPart,
                              krbRc4.EtypeRc4Hmac, asRep = false)
  result.isError = false

proc serveOne(cfg: var MockKdcConfig; conn: Socket;
              tally: var MockKdcResult): bool =
  ## Handle one request on an already-accepted socket. Returns false
  ## if the client closed without sending a complete request.
  var lenBuf = newString(4)
  var got = 0
  while got < 4:
    let n = conn.recv(lenBuf[got].addr, 4 - got)
    if n <= 0: return false
    got += n
  let n =
    (int(byte(lenBuf[0])) shl 24) or
    (int(byte(lenBuf[1])) shl 16) or
    (int(byte(lenBuf[2])) shl 8) or
    int(byte(lenBuf[3]))
  var body = newSeq[byte](n)
  var consumed = 0
  while consumed < n:
    var chunk = newString(n - consumed)
    let r = conn.recv(chunk[0].addr, n - consumed)
    if r <= 0:
      tally.err = "client disconnected mid-request"
      return false
    for i in 0 ..< r: body[consumed + i] = byte(chunk[i].ord)
    consumed += r

  if body.len == 0:
    tally.err = "empty request"
    return false
  let isAsReq = body[0] == 0x6A'u8
  let isTgsReq = body[0] == 0x6C'u8
  var reply: seq[byte]
  if isAsReq:
    let (r, _) = handleAsReq(cfg, body)
    reply = r
  elif isTgsReq:
    let (r, _) = handleTgsReq(cfg, body, "host", "fake.example.com")
    reply = r
  else:
    tally.err = "unknown request tag 0x" & $body[0]
    return false

  inc tally.requestsServed
  var pref = newString(4)
  pref[0] = char((reply.len shr 24) and 0xff)
  pref[1] = char((reply.len shr 16) and 0xff)
  pref[2] = char((reply.len shr 8) and 0xff)
  pref[3] = char(reply.len and 0xff)
  var replyStr = newString(reply.len)
  for i, b in reply: replyStr[i] = char(b)
  conn.send(pref & replyStr)
  true

proc serveExpected*(cfg: var MockKdcConfig;
                    expectedRequests: int): MockKdcResult =
  ## Serve exactly ``expectedRequests`` requests across one or more
  ## TCP connections (the client opens a fresh connection per request).
  let listener = newSocket()
  listener.setSockOpt(OptReuseAddr, true)
  listener.bindAddr(Port(cfg.port), "127.0.0.1")
  listener.listen()
  while result.requestsServed < expectedRequests:
    var conn: Socket
    listener.accept(conn)
    discard serveOne(cfg, conn, result)
    conn.close()
    if result.err.len > 0:
      listener.close()
      return
  listener.close()
