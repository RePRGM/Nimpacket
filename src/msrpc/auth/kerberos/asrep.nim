## auth/kerberos/asrep.nim — AS-REP parser.
##
## AS-REP layout (RFC 4120 §5.4.2)::
##
##   AS-REP ::= [APPLICATION 11] SEQUENCE {
##       pvno     [0]  INTEGER (5),
##       msg-type [1]  INTEGER (11),
##       padata   [2]  SEQUENCE OF PA-DATA OPTIONAL,
##       crealm   [3]  Realm,
##       cname    [4]  PrincipalName,
##       ticket   [5]  Ticket,
##       enc-part [6]  EncryptedData    -- EncASRepPart
##   }
##
##   Ticket ::= [APPLICATION 1] SEQUENCE { ... }
##
##   EncASRepPart ::= [APPLICATION 25] EncKDCRepPart
##   EncKDCRepPart ::= SEQUENCE {
##       key      [0] EncryptionKey,
##       last-req [1] LastReq, ...
##       ...
##   }
##
## We extract just enough to drive subsequent TGS-REQ and AP-REQ
## construction: the encrypted part of the AS-REP (which we'll
## decrypt with the user's long-term key), and the raw Ticket bytes
## (which we'll forward verbatim).

import ../../common/buffers
import ../spnego/asn1
import messages, rc4 as krbRc4, aes as krbAes, etype

type
  AsRepEnvelope* = object
    crealm*: string
    cname*: string
    ticketBytes*: seq[byte]    ## raw [APPLICATION 1] SEQUENCE — keep verbatim
    encEtype*: uint32
    encCipher*: seq[byte]

  EncKdcRepPart* = object
    sessionKey*: seq[byte]
    sessionEtype*: uint32

# --- top-level AS-REP parser --------------------------------------

proc parseAsRep*(data: openArray[byte]): AsRepEnvelope =
  let b = newBuffer(@data)
  let outerLen = b.derReadTag(appConstructed(appAsRep))
  let outerEnd = b.pos + outerLen
  discard b.derReadTag(tagSequence)
  while b.pos < outerEnd:
    let tag = b.peekByte()
    if (tag and 0xE0) != 0xA0: break
    let fieldNum = int(tag and 0x1F)
    let l = b.derReadTag(tag)
    let endPos = b.pos + l
    case fieldNum
    of 3: # crealm
      let sLen = b.derReadTag(0x1B'u8)
      for _ in 0 ..< sLen: result.crealm.add char(b.readByte())
    of 4: # cname
      discard b.derReadTag(tagSequence)
      # name-type [0]
      let ntL = b.derReadTag(ctxConstructed(0))
      b.skip(ntL)
      let nsL = b.derReadTag(ctxConstructed(1))
      discard nsL
      discard b.derReadTag(tagSequence)
      while b.pos < endPos:
        let t = b.peekByte()
        if t == 0x1B'u8:
          let l2 = b.derReadTag(0x1B'u8)
          if result.cname.len > 0: result.cname.add '/'
          for _ in 0 ..< l2: result.cname.add char(b.readByte())
        else: break
    of 5: # ticket — keep raw bytes (tag + len + value)
      let startPos = b.pos - 2          # rough: tag byte + length byte
      # For DER encoded structures with length we need to also account
      # for long-form lengths. Simpler: re-emit the whole [5] field as
      # `[APPLICATION 1] ...` by reading from the tag position.
      let tagStart = b.pos              # we're now inside the [5] tagged value
      # The ticket itself starts here. Read it as a self-contained
      # [APPLICATION 1] structure; its first byte is 0x61.
      let tagByte = b.readByte()
      doAssert tagByte == appConstructed(appTicket),
        "ticket should start with [APPLICATION 1]"
      let tLen = b.derReadLen()
      var ticket = newSeq[byte](b.pos - tagStart + tLen)
      ticket[0] = tagByte
      # Re-encode length
      let lenBuf = newBuffer()
      lenBuf.derWriteLen(tLen)
      let lenBytes = lenBuf.consumed
      for i, x in lenBytes: ticket[1 + i] = x
      var off = 1 + lenBytes.len
      let body = b.readBytes(tLen)
      for x in body:
        ticket[off] = x
        inc off
      ticket.setLen(off)
      result.ticketBytes = ticket
      discard startPos
    of 6: # enc-part : EncryptedData
      discard b.derReadTag(tagSequence)
      # [0] etype
      discard b.derReadTag(ctxConstructed(0))
      let etLen = b.derReadTag(0x02'u8)
      var et = 0
      for _ in 0 ..< etLen: et = (et shl 8) or int(b.readByte())
      result.encEtype = uint32(et)
      while b.pos < endPos:
        let t = b.peekByte()
        if t == ctxConstructed(2):
          discard b.derReadTag(ctxConstructed(2))
          let cLen = b.derReadTag(tagOctetString)
          result.encCipher = b.readBytes(cLen)
        elif t == ctxConstructed(1):  # optional kvno
          let kL = b.derReadTag(ctxConstructed(1))
          b.skip(kL)
        else: break
    else:
      discard
    b.seek(endPos)
  b.seek(outerEnd)

# --- EncKDCRepPart parser (after decryption) ---------------------

proc parseEncKdcRepPart*(plaintext: openArray[byte]): EncKdcRepPart =
  ## Only pull out the session key — that's what TGS-REQ needs.
  ## Other fields (last-req, nonce, key-expiration, flags, authtime,
  ## starttime, endtime, ...) are nice-to-have for full client logic.
  let b = newBuffer(@plaintext)
  let outerLen = b.derReadTag(appConstructed(25))   # [APPLICATION 25]
  discard outerLen
  let seqLen = b.derReadTag(tagSequence)
  let seqEnd = b.pos + seqLen
  while b.pos < seqEnd:
    let tag = b.peekByte()
    if (tag and 0xE0) != 0xA0: break
    let fieldNum = int(tag and 0x1F)
    let l = b.derReadTag(tag)
    let endPos = b.pos + l
    if fieldNum == 0:
      # EncryptionKey ::= SEQUENCE { keytype [0] Int32, keyvalue [1] OCTET STRING }
      discard b.derReadTag(tagSequence)
      discard b.derReadTag(ctxConstructed(0))
      let etLen = b.derReadTag(0x02'u8)
      var et = 0
      for _ in 0 ..< etLen: et = (et shl 8) or int(b.readByte())
      result.sessionEtype = uint32(et)
      discard b.derReadTag(ctxConstructed(1))
      let vLen = b.derReadTag(tagOctetString)
      result.sessionKey = b.readBytes(vLen)
      b.seek(endPos)
      return
    else:
      b.seek(endPos)

# --- decrypt AS-REP enc-part with RC4 ------------------------------

proc decryptAsRepRc4*(env: AsRepEnvelope; userKey: openArray[byte]):
                      tuple[plain: seq[byte]; ok: bool] =
  ## AS-REP enc-part uses key usage 3 with the user's long-term key
  ## (RFC 4120 §7.5.1 / RFC 4757).
  if env.encEtype != krbRc4.EtypeRc4Hmac:
    return (plain: @[], ok: false)
  let (plain, ok) = krbRc4.rc4HmacDecrypt(userKey, env.encCipher, usage = 3)
  result = (plain: plain, ok: ok)

proc decryptAsRepAes*(env: AsRepEnvelope; userKey: openArray[byte]):
                      tuple[plain: seq[byte]; ok: bool] =
  ## AS-REP enc-part for ETYPE 17 / 18 uses key usage 3 with the
  ## user's long-term AES key.
  if env.encEtype != EtypeAes128 and env.encEtype != EtypeAes256:
    return (plain: @[], ok: false)
  let (plain, ok) = krbAes.aesDecrypt(userKey, env.encCipher, usage = 3'u32)
  result = (plain: plain, ok: ok)

proc decryptAsRep*(env: AsRepEnvelope; userKey: openArray[byte]):
                   tuple[plain: seq[byte]; ok: bool] =
  ## Etype-dispatched AS-REP decryption. Caller supplies the correct
  ## long-term key for the etype (NT-hash for RC4, AES key from
  ## stringToKey for AES).
  case env.encEtype
  of krbRc4.EtypeRc4Hmac: result = decryptAsRepRc4(env, userKey)
  of EtypeAes128, EtypeAes256: result = decryptAsRepAes(env, userKey)
  else: result = (plain: @[], ok: false)
