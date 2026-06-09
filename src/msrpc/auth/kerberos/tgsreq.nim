## auth/kerberos/tgsreq.nim — TGS-REQ builder + TGS-REP parser.
##
## TGS-REQ is structurally identical to AS-REQ (RFC 4120 §5.4.1) but:
##   - application tag = [APPLICATION 12]
##   - msg-type = 12
##   - cname is omitted from req-body (KDC derives it from AP-REQ)
##   - pa-data MUST contain a PA-TGS-REQ (type 1) whose value is the
##     DER-encoded AP-REQ to krbtgt — this proves possession of the TGT.
##
## TGS-REP encrypted part is encrypted with the TGS session key. For
## RC4-HMAC the usage number is 8 (no sub-session key in authenticator)
## per RFC 4120 §7.5.1 + RFC 4757 §3.

import ../../common/buffers
import ../spnego/asn1
import messages, rc4 as krbRc4, asrep

# --- KDC-options helpers -------------------------------------------

const
  KdcOptForwardable*    = 1    ## RFC 4120 §5.4.1 bit positions (MSB = bit 0)
  KdcOptRenewable*      = 8
  KdcOptCnameInAddlTkt* = 14   ## a.k.a. constrained-delegation (S4U2proxy)
  KdcOptCanonicalize*   = 15
  KdcOptEncTktInSkey*   = 28

proc kdcOptionFlags*(bits: openArray[int]): array[4, byte] =
  ## Pack KDC-option bit positions into the 32-bit flag field (bit 0 = MSB
  ## of the first byte), as carried in the kdc-options BIT STRING.
  for b in bits:
    result[b div 8] = result[b div 8] or byte(0x80'u8 shr (b mod 8))

# --- pa-data + integer helpers -------------------------------------

proc derUInt(v: int): seq[byte] =
  ## Minimal big-endian DER INTEGER content for a non-negative value.
  var n = v
  while n > 0:
    result.insert(byte(n and 0xff), 0)
    n = n shr 8
  if result.len == 0: result = @[0'u8]
  if (result[0] and 0x80) != 0: result.insert(0'u8, 0)

proc paDataEntry*(padataType: int; value: openArray[byte]): seq[byte] =
  ## One PA-DATA entry: SEQUENCE { padata-type [1] Int32, padata-value [2] OCTET STRING }.
  let e = newBuffer()
  e.writeBytes(fieldTag(1, derTLV(0x02'u8, derUInt(padataType))))
  e.writeBytes(fieldTag(2, derTLV(tagOctetString, value)))
  result = derTLV(tagSequence, e.consumed)

proc encodeNonce(nonce: uint32): seq[byte] =
  var nb = @[byte(nonce shr 24), byte(nonce shr 16), byte(nonce shr 8), byte(nonce)]
  while nb.len > 1 and nb[0] == 0 and (nb[1] and 0x80) == 0: nb.delete(0)
  result = derTLV(0x02'u8, nb)

proc encodeEtypeSeq(etypes: openArray[uint32]): seq[byte] =
  let etypeBuf = newBuffer()
  for et in etypes:
    var ebytes: seq[byte] = @[]
    var v = et
    while v > 0:
      ebytes.insert(byte(v and 0xFF), 0)
      v = v shr 8
    if ebytes.len == 0: ebytes = @[0'u8]
    etypeBuf.writeBytes(derTLV(0x02'u8, ebytes))
  result = derTLV(tagSequence, etypeBuf.consumed)

# --- TGS-REQ builders ----------------------------------------------

proc buildTgsReqRaw*(realm: string;
                     sname: openArray[byte];
                     nonce: uint32;
                     etypes: openArray[uint32];
                     till: string;
                     apReq: openArray[byte];
                     kdcFlags: array[4, byte] = [0'u8, 0, 0, 0];
                     extraPaData: openArray[byte] = @[];
                     additionalTickets: openArray[byte] = @[]): seq[byte] =
  ## Flexible TGS-REQ core. ``sname`` is a pre-encoded PrincipalName,
  ## ``extraPaData`` is zero or more pre-encoded PA-DATA entries appended after
  ## the mandatory PA-TGS-REQ, and ``additionalTickets`` is a pre-encoded Ticket
  ## (or concatenated Tickets) placed in req-body field [11] for S4U2proxy.

  # PA-DATA: PA-TGS-REQ (the AP-REQ to krbtgt), then any extra entries.
  let pa = newBuffer()
  pa.writeBytes(fieldTag(1, derTLV(0x02'u8, @[byte(PaTgsReq)])))
  pa.writeBytes(fieldTag(2, derTLV(tagOctetString, apReq)))
  let paEntries = newBuffer()
  paEntries.writeBytes(derTLV(tagSequence, pa.consumed))
  if extraPaData.len > 0: paEntries.writeBytes(extraPaData)
  let paDataSeq = derTLV(tagSequence, paEntries.consumed)

  let kdcOptions = derTLV(tagBitString,
                          @[0x00'u8, kdcFlags[0], kdcFlags[1], kdcFlags[2], kdcFlags[3]])
  let realmEnc = derTLV(0x1B'u8, cast[seq[byte]](realm))
  let tillEnc = derTLV(0x18'u8, cast[seq[byte]](till))

  # req-body — NOTE: no cname for TGS-REQ.
  let reqBody = newBuffer()
  reqBody.writeBytes(fieldTag(0, kdcOptions))
  reqBody.writeBytes(fieldTag(2, realmEnc))
  reqBody.writeBytes(fieldTag(3, @sname))
  reqBody.writeBytes(fieldTag(5, tillEnc))
  reqBody.writeBytes(fieldTag(7, encodeNonce(nonce)))
  reqBody.writeBytes(fieldTag(8, encodeEtypeSeq(etypes)))
  if additionalTickets.len > 0:
    reqBody.writeBytes(fieldTag(11, derTLV(tagSequence, additionalTickets)))
  let reqBodyEnc = derTLV(tagSequence, reqBody.consumed)

  # KDC-REQ SEQUENCE
  let body = newBuffer()
  body.writeBytes(fieldTag(1, derTLV(0x02'u8, @[5'u8])))   # pvno = 5
  body.writeBytes(fieldTag(2, derTLV(0x02'u8, @[byte(appTgsReq)])))
  body.writeBytes(fieldTag(3, paDataSeq))
  body.writeBytes(fieldTag(4, reqBodyEnc))
  result = derTLV(appConstructed(appTgsReq), derTLV(tagSequence, body.consumed))

proc buildTgsReq*(realm: string;
                  serviceClass, serviceHost: string;
                  nonce: uint32;
                  etypes: openArray[uint32];
                  till: string;
                  apReq: openArray[byte]): seq[byte] =
  ## Build a TGS-REQ that asks for a service ticket for
  ## ``serviceClass/serviceHost`` (e.g. "host"/"dc01.corp.local").
  ##
  ## ``apReq`` is the bare AP-REQ to krbtgt (NOT wrapped in GSS-API).
  buildTgsReqRaw(realm, principalName(NtSrvHst, [serviceClass, serviceHost]),
                 nonce, etypes, till, apReq)

# --- TGS-REP parsing -----------------------------------------------

proc parseTgsRep*(data: openArray[byte]): AsRepEnvelope =
  ## TGS-REP is structurally identical to AS-REP but wrapped in
  ## [APPLICATION 13]. We reuse the AS-REP parser by retagging.
  if data.len == 0 or data[0] != 0x6D'u8:
    raise newException(ValueError, "not a TGS-REP")
  var rewritten = newSeq[byte](data.len)
  for i in 0 ..< data.len: rewritten[i] = data[i]
  rewritten[0] = 0x6B'u8   # AS-REP tag, so we can reuse the parser
  result = parseAsRep(rewritten)

proc decryptTgsRepRc4*(env: AsRepEnvelope;
                       tgtSessionKey: openArray[byte]):
                       tuple[plain: seq[byte]; ok: bool] =
  ## TGS-REP enc-part is encrypted under the TGT session key with
  ## key usage 8 (RFC 4120 §7.5.1).
  if env.encEtype != krbRc4.EtypeRc4Hmac:
    return (plain: @[], ok: false)
  let (plain, ok) = krbRc4.rc4HmacDecrypt(tgtSessionKey, env.encCipher,
                                          usage = 8'u32)
  result = (plain: plain, ok: ok)
