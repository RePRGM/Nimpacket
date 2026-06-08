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

# --- TGS-REQ builder -----------------------------------------------

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

  # PA-DATA: SEQUENCE OF { padata-type [1] = PaTgsReq, padata-value [2] = AP-REQ }
  let pa = newBuffer()
  pa.writeBytes(fieldTag(1, derTLV(0x02'u8, @[byte(PaTgsReq)])))
  pa.writeBytes(fieldTag(2, derTLV(tagOctetString, apReq)))
  let paEntry = derTLV(tagSequence, pa.consumed)
  let paDataSeq = derTLV(tagSequence, paEntry)

  # kdc-options BIT STRING — keep defaults (no forwarding/proxying)
  let kdcOptions = derTLV(tagBitString, @[0x00'u8, 0, 0, 0, 0])

  # sname: PrincipalName { name-type NT-SRV-HST, [serviceClass, serviceHost] }
  let sname = principalName(NtSrvHst, [serviceClass, serviceHost])

  let realmEnc = derTLV(0x1B'u8, cast[seq[byte]](realm))
  let tillEnc = derTLV(0x18'u8, cast[seq[byte]](till))

  # nonce UInt32
  var nonceBytes = @[byte(nonce shr 24), byte(nonce shr 16),
                     byte(nonce shr 8), byte(nonce)]
  while nonceBytes.len > 1 and nonceBytes[0] == 0 and
        (nonceBytes[1] and 0x80) == 0:
    nonceBytes.delete(0)
  let nonceEnc = derTLV(0x02'u8, nonceBytes)

  # etype SEQUENCE OF Int32
  let etypeBuf = newBuffer()
  for et in etypes:
    var ebytes: seq[byte] = @[]
    var v = et
    while v > 0:
      ebytes.insert(byte(v and 0xFF), 0)
      v = v shr 8
    if ebytes.len == 0: ebytes = @[0'u8]
    etypeBuf.writeBytes(derTLV(0x02'u8, ebytes))
  let etypeEnc = derTLV(tagSequence, etypeBuf.consumed)

  # req-body — NOTE: no cname for TGS-REQ.
  let reqBody = newBuffer()
  reqBody.writeBytes(fieldTag(0, kdcOptions))
  reqBody.writeBytes(fieldTag(2, realmEnc))
  reqBody.writeBytes(fieldTag(3, sname))
  reqBody.writeBytes(fieldTag(5, tillEnc))
  reqBody.writeBytes(fieldTag(7, nonceEnc))
  reqBody.writeBytes(fieldTag(8, etypeEnc))
  let reqBodyEnc = derTLV(tagSequence, reqBody.consumed)

  # KDC-REQ SEQUENCE
  let body = newBuffer()
  body.writeBytes(fieldTag(1, derTLV(0x02'u8, @[5'u8])))   # pvno = 5
  body.writeBytes(fieldTag(2, derTLV(0x02'u8, @[byte(appTgsReq)])))
  body.writeBytes(fieldTag(3, paDataSeq))
  body.writeBytes(fieldTag(4, reqBodyEnc))
  let inner = derTLV(tagSequence, body.consumed)

  result = derTLV(appConstructed(appTgsReq), inner)

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
