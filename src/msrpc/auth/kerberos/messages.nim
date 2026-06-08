## auth/kerberos/messages.nim — KRB5 ASN.1 structures (subset).
##
## We model just the structures needed for password-based AS-REQ
## against an MIT or AD KDC and the resulting AP-REQ token. Full KRB5
## has ~30 more structures; those land in follow-ups.
##
## Spec references: RFC 4120. AD-specific tags: MS-KILE.

import std/[strutils, times]
import ../../common/buffers
import ../spnego/asn1

# Application tags used in KRB5 (RFC 4120 §5.4):
#   [APPLICATION 1]  Ticket
#   [APPLICATION 2]  Authenticator
#   [APPLICATION 10] AS-REQ
#   [APPLICATION 11] AS-REP
#   [APPLICATION 12] TGS-REQ
#   [APPLICATION 13] TGS-REP
#   [APPLICATION 14] AP-REQ
#   [APPLICATION 15] AP-REP
#   [APPLICATION 30] KRB-ERROR

const
  appTicket*       = 1
  appAsReq*        = 10
  appAsRep*        = 11
  appTgsReq*       = 12
  appTgsRep*       = 13
  appApReq*        = 14
  appKrbError*     = 30

# Name types
const
  NtPrincipal*  = 1
  NtSrvInst*    = 2
  NtSrvHst*     = 3

# Pa-data types
const
  PaTgsReq*       = 1
  PaEncTimestamp* = 2
  PaPwSalt*       = 3

# --- helpers for KRB-Generalized-Time -----------------------------

proc kerberosTimestamp*(t: Time): string =
  ## YYYYMMDDhhmmssZ format per RFC 4120 §5.2.3.
  ## std/times' format pattern can't emit a literal 'Z', so build by hand.
  let dt = t.utc
  result = dt.format("yyyyMMddHHmmss") & "Z"

# --- field-tagged builder helpers ---------------------------------

proc fieldTag*(n: int; inner: openArray[byte]): seq[byte] =
  ## Wrap ``inner`` in a `[n]` EXPLICIT context-class constructed tag.
  derTLV(ctxConstructed(n), inner)

proc kerbStringSeq*(strs: openArray[string]): seq[byte] =
  ## SEQUENCE OF KerberosString (GeneralString tag 0x1B). We use the
  ## simpler approach: emit each as an OCTET STRING tagged with 0x1B.
  let b = newBuffer()
  for s in strs:
    b.writeBytes(derTLV(0x1B'u8, cast[seq[byte]](s)))
  result = derTLV(tagSequence, b.consumed)

proc principalName*(nameType: int; nameStrings: openArray[string]): seq[byte] =
  ## PrincipalName ::= SEQUENCE {
  ##     name-type   [0] Int32,
  ##     name-string [1] SEQUENCE OF KerberosString }
  let inner = newBuffer()
  # name-type [0]
  inner.writeBytes(fieldTag(0, derTLV(tagSequence,
                                       @[])))   # placeholder, replace below
  # Actually we need an INTEGER inside the [0] tag. Replace:
  let intLit =
    if nameType >= 0 and nameType <= 127:
      @[byte(nameType)]
    else: @[0'u8, byte(nameType)]   # simple unsigned encode
  let inner2 = newBuffer()
  inner2.writeBytes(fieldTag(0, derTLV(0x02'u8, intLit)))
  inner2.writeBytes(fieldTag(1, kerbStringSeq(nameStrings)))
  result = derTLV(tagSequence, inner2.consumed)

# --- KRB-Error parsing (the most common AS-REP outcome on first try)

type
  KrbError* = object
    errorCode*: int
    realm*: string
    sname*: string
    eText*: string
    eData*: seq[byte]

proc parseKrbError*(blob: openArray[byte]): KrbError =
  ## Parse the application-30 KRB-ERROR. Stops at e-data so the caller
  ## can decide what to do with PA-ETYPE-INFO2 etc. Best-effort: skips
  ## fields it doesn't know.
  let b = newBuffer(@blob)
  # [APPLICATION 30] {
  let outerLen = b.derReadTag(appConstructed(appKrbError))
  let outerEnd = b.pos + outerLen
  discard b.derReadTag(tagSequence)
  # Iterate tagged context fields; skim past anything that isn't a
  # field we want.
  while b.pos < outerEnd:
    let tag = b.peekByte()
    if (tag and 0xE0) != 0xA0:
      break
    let fieldNum = int(tag and 0x1F)
    let l = b.derReadTag(tag)
    let endPos = b.pos + l
    case fieldNum
    of 6:  # error-code
      let intLen = b.derReadTag(0x02'u8)
      var v = 0
      for _ in 0 ..< intLen:
        v = (v shl 8) or int(b.readByte())
      result.errorCode = v
    of 9:  # realm
      let sLen = b.derReadTag(0x1B'u8)
      for _ in 0 ..< sLen: result.realm.add char(b.readByte())
    of 10: # sname — PrincipalName; we just dump the joined strings
      discard b.derReadTag(tagSequence)
      # name-type [0]
      let ntL = b.derReadTag(ctxConstructed(0))
      b.skip(ntL)
      let nsL = b.derReadTag(ctxConstructed(1))
      discard nsL
      discard b.derReadTag(tagSequence)
      # collect any GeneralString tokens
      while b.pos < endPos:
        let t = b.peekByte()
        if t == 0x1B'u8:
          let l2 = b.derReadTag(0x1B'u8)
          if result.sname.len > 0: result.sname.add '/'
          for _ in 0 ..< l2: result.sname.add char(b.readByte())
        else: break
    of 11: # e-text
      let sLen = b.derReadTag(0x1B'u8)
      for _ in 0 ..< sLen: result.eText.add char(b.readByte())
    of 12: # e-data
      let eL = b.derReadTag(tagOctetString)
      result.eData = b.readBytes(eL)
    else:
      b.seek(endPos)
    b.seek(endPos)
  b.seek(outerEnd)

# --- AS-REQ builder (minimal) ------------------------------------

proc buildAsReq*(realm, clientPrincipal, serviceName: string;
                 nonce: uint32; etypes: openArray[uint32];
                 till: string;
                 preAuth: openArray[byte] = @[]): seq[byte] =
  ## A minimal AS-REQ message suitable for the first (no-PA-data) try
  ## that AD KDCs reject with PA-DATA-REQUIRED + PA-ETYPE-INFO2. The
  ## caller can then re-send with the encrypted-timestamp pre-auth.
  ##
  ## ``serviceName`` is typically "krbtgt".

  # PA-DATA: SEQUENCE OF (padata-type [1], padata-value [2])
  let paDataList = newBuffer()
  if preAuth.len > 0:
    let pa = newBuffer()
    pa.writeBytes(fieldTag(1, derTLV(0x02'u8, @[byte(PaEncTimestamp)])))
    pa.writeBytes(fieldTag(2, derTLV(tagOctetString, preAuth)))
    paDataList.writeBytes(derTLV(tagSequence, pa.consumed))

  # kdc-options BIT STRING (32 bits, all zero by default)
  let kdcOptions = derTLV(tagBitString, @[0x00'u8, 0, 0, 0, 0])

  # cname PrincipalName
  let cname = principalName(NtPrincipal, [clientPrincipal])
  # sname PrincipalName
  let sname = principalName(NtSrvInst, [serviceName, realm])

  # realm KerberosString
  let realmEnc = derTLV(0x1B'u8, cast[seq[byte]](realm))

  # till KerberosTime (GeneralizedTime tag 0x18)
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

  # req-body SEQUENCE
  let reqBody = newBuffer()
  reqBody.writeBytes(fieldTag(0, kdcOptions))
  reqBody.writeBytes(fieldTag(1, cname))
  reqBody.writeBytes(fieldTag(2, realmEnc))
  reqBody.writeBytes(fieldTag(3, sname))
  reqBody.writeBytes(fieldTag(5, tillEnc))
  reqBody.writeBytes(fieldTag(7, nonceEnc))
  reqBody.writeBytes(fieldTag(8, etypeEnc))
  let reqBodyEnc = derTLV(tagSequence, reqBody.consumed)

  # KDC-REQ SEQUENCE
  let body = newBuffer()
  body.writeBytes(fieldTag(1, derTLV(0x02'u8, @[5'u8])))   # pvno = 5
  body.writeBytes(fieldTag(2, derTLV(0x02'u8, @[byte(appAsReq)])))
  if paDataList.consumed.len > 0:
    let pdSeq = derTLV(tagSequence, paDataList.consumed)
    body.writeBytes(fieldTag(3, pdSeq))
  body.writeBytes(fieldTag(4, reqBodyEnc))
  let inner = derTLV(tagSequence, body.consumed)

  result = derTLV(appConstructed(appAsReq), inner)
