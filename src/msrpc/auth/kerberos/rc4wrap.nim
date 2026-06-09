## auth/kerberos/rc4wrap.nim — RFC 4757 §7.3 RC4-HMAC GSS-API Wrap
## and MIC tokens.
##
## Completely different layout from the RFC 4121 AES tokens — separate
## key derivations, separate token structure, separate sequence
## handling. We need both because RC4-HMAC and AES are two different
## ETYPEs in AD; a single library that doesn't support both will fail
## against any account stuck on legacy RC4 (and they exist in
## production AD environments more often than you'd hope).
##
## Token layout (the 32-byte inner token; the optional GSS-API ASN.1
## outer wrap is added separately for SPNEGO):
##
##   ┌──────────────────────────────────────────────────────────────┐
##   │  0..1   TOK_ID    0x02 0x01 (Wrap) or 0x01 0x01 (MIC)        │
##   │  2..3   SGN_ALG   0x11 0x00 (HMAC-MD5; the only modern alg)  │
##   │  4..5   SEAL_ALG  0x10 0x00 (RC4) or 0xFF 0xFF (sign-only)   │
##   │  6..7   Filler    0xFF 0xFF                                  │
##   │  8..15  SND_SEQ   encrypted [BE32(seq) || direction marker]  │
##   │ 16..23  SGN_CKSUM HMAC-MD5 over (T0 || confounder || data),  │
##   │                   truncated to 8 bytes                       │
##   │ 24..31  Confounder encrypted 8 random bytes                  │
##   └──────────────────────────────────────────────────────────────┘
##
## For Wrap-with-confidentiality, the data bytes are also RC4-encrypted
## with the same stream that produced the encrypted confounder. The
## token is sent BEFORE the encrypted data on the wire (caller's
## responsibility to place them in the right RPC fields).
##
## Key derivation (RFC 4757 §7.3 — note the cascaded HMAC):
##   K           = session key (16 bytes, the RC4-HMAC long-term key)
##   Ksign       = HMAC-MD5(K, "signaturekey\0")
##   Kseq_seed   = HMAC-MD5(K, BE32(0))                  -- usage = 0
##   Kseq        = HMAC-MD5(Kseq_seed, SGN_CKSUM)
##   Kcrypt_seed = HMAC-MD5(K, BE32(1024))               -- MS-KILE specific
##   Kcrypt      = HMAC-MD5(Kcrypt_seed, BE32(seq))
##
## The acceptor direction XORs every byte of Kcrypt_seed with 0xF0
## *before* HMAC'ing again — this gives the two directions distinct
## per-message keys without renegotiation.

import ../../crypto/[md5, hmac, rc4 as rc4cipher, rand]

const
  TokIdRc4Wrap* = [0x02'u8, 0x01]
  TokIdRc4Mic*  = [0x01'u8, 0x01]
  SgnAlgHmac*   = [0x11'u8, 0x00]
  SealAlgRc4*   = [0x10'u8, 0x00]
  SealAlgNone*  = [0xFF'u8, 0xFF]

  Rc4TokenLen*       = 32
  Rc4ConfounderLen*  = 8
  Rc4SignatureKey*   = "signaturekey\0"

# --- key derivation helpers ---------------------------------------

proc deriveKsign*(sessionKey: openArray[byte]): array[16, byte] =
  ## Ksign = HMAC-MD5(K, "signaturekey\0").
  let salt = cast[seq[byte]](@Rc4SignatureKey)
  result = hmacMd5(sessionKey, salt)

proc beU32(v: uint32): array[4, byte] {.inline.} =
  result[0] = byte((v shr 24) and 0xff)
  result[1] = byte((v shr 16) and 0xff)
  result[2] = byte((v shr 8) and 0xff)
  result[3] = byte(v and 0xff)

proc deriveKseq*(sessionKey: openArray[byte];
                  sgnCksum: openArray[byte]): array[16, byte] =
  ## Kseq for encrypting the SND_SEQ field. Cascaded HMAC keyed first
  ## by K with usage = 0, then by that with the checksum.
  let seed = hmacMd5(sessionKey, beU32(0'u32))
  result = hmacMd5(seed, sgnCksum)

proc deriveKcrypt*(sessionKey: openArray[byte]; seq: uint32;
                   isInitiator: bool): array[16, byte] =
  ## Kcrypt for encrypting confounder + body. usage = 1024 (MS-KILE).
  ## Acceptor direction XORs the seed with 0xF0 per byte before the
  ## second HMAC — gives the two directions distinct per-seq keys.
  var seed = hmacMd5(sessionKey, beU32(1024'u32))
  if not isInitiator:
    for i in 0 ..< 16: seed[i] = seed[i] xor 0xF0'u8
  result = hmacMd5(seed, beU32(seq))

# --- 8-byte token header used as the SGN_CKSUM input prefix -------

proc buildRc4Header(tokId: openArray[byte]; encrypt: bool): array[8, byte] =
  result[0] = tokId[0]
  result[1] = tokId[1]
  result[2] = SgnAlgHmac[0]
  result[3] = SgnAlgHmac[1]
  let sealAlg = if encrypt: SealAlgRc4 else: SealAlgNone
  result[4] = sealAlg[0]
  result[5] = sealAlg[1]
  result[6] = 0xFF'u8
  result[7] = 0xFF'u8

# --- Wrap (with confidentiality) ----------------------------------

proc rc4WrapSeal*(sessionKey: openArray[byte];
                  data: var openArray[byte]; dataLen: int;
                  seq: uint32; isInitiator: bool): seq[byte] =
  ## Encrypt ``data[0 ..< dataLen]`` in place using RC4 and return the
  ## 32-byte Wrap token. Caller puts the token in the sec_trailer's
  ## auth_value and leaves the (now-encrypted) data in the PDU body.
  doAssert dataLen >= 0 and dataLen <= data.len

  let ksign = deriveKsign(sessionKey)
  let header = buildRc4Header(TokIdRc4Wrap, encrypt = true)

  # Confounder: 8 random bytes. Encrypted together with data using
  # the same RC4 stream (single Kcrypt produces one keystream).
  var confounder: array[Rc4ConfounderLen, byte]
  let cb = randomBytes(Rc4ConfounderLen)
  for i in 0 ..< Rc4ConfounderLen: confounder[i] = cb[i]

  # SGN_CKSUM = HMAC-MD5(Ksign, MD5(header || confounder || data))[:8]
  var hashInput = newSeq[byte](8 + Rc4ConfounderLen + dataLen)
  for i in 0 ..< 8: hashInput[i] = header[i]
  for i in 0 ..< Rc4ConfounderLen: hashInput[8 + i] = confounder[i]
  for i in 0 ..< dataLen: hashInput[8 + Rc4ConfounderLen + i] = data[i]
  let inner = md5(hashInput)
  let cksumFull = hmacMd5(ksign, inner)
  var sgnCksum: array[8, byte]
  for i in 0 ..< 8: sgnCksum[i] = cksumFull[i]

  # SND_SEQ: encrypted (BE32(seq) || 4 direction bytes) under Kseq.
  let kseq = deriveKseq(sessionKey, sgnCksum)
  let seqBytes = beU32(seq)
  var sndSeqPlain: array[8, byte]
  for i in 0 ..< 4: sndSeqPlain[i] = seqBytes[i]
  let dirByte = if isInitiator: 0x00'u8 else: 0xFF'u8
  for i in 4 ..< 8: sndSeqPlain[i] = dirByte
  let sndSeqEnc = rc4cipher.rc4(kseq, sndSeqPlain)

  # Encrypt confounder + data with one continuous Kcrypt stream.
  let kcrypt = deriveKcrypt(sessionKey, seq, isInitiator)
  var encStream = newSeq[byte](Rc4ConfounderLen + dataLen)
  for i in 0 ..< Rc4ConfounderLen: encStream[i] = confounder[i]
  for i in 0 ..< dataLen: encStream[Rc4ConfounderLen + i] = data[i]
  let encrypted = rc4cipher.rc4(kcrypt, encStream)

  # Stuff the encrypted body back into the caller's data buffer.
  for i in 0 ..< dataLen: data[i] = encrypted[Rc4ConfounderLen + i]

  # Assemble the 32-byte token.
  result = newSeq[byte](Rc4TokenLen)
  for i in 0 ..< 8:  result[i]      = header[i]
  for i in 0 ..< 8:  result[8 + i]  = sndSeqEnc[i]
  for i in 0 ..< 8:  result[16 + i] = sgnCksum[i]
  for i in 0 ..< 8:  result[24 + i] = encrypted[i]    # encrypted confounder

proc rc4WrapUnseal*(sessionKey: openArray[byte];
                    data: var openArray[byte]; dataLen: int;
                    token: openArray[byte]; isInitiator: bool):
                    tuple[seq: uint32; ok: bool] =
  ## Verify+decrypt an RC4 Wrap token.
  if token.len != Rc4TokenLen:
    return (seq: 0'u32, ok: false)
  if token[0] != TokIdRc4Wrap[0] or token[1] != TokIdRc4Wrap[1]:
    return (seq: 0'u32, ok: false)
  if token[2] != SgnAlgHmac[0] or token[3] != SgnAlgHmac[1]:
    return (seq: 0'u32, ok: false)
  if token[4] != SealAlgRc4[0] or token[5] != SealAlgRc4[1]:
    return (seq: 0'u32, ok: false)

  # Extract the encrypted fields.
  var sndSeqEnc, sgnCksumWire, encConfounder: array[8, byte]
  for i in 0 ..< 8: sndSeqEnc[i]    = token[8 + i]
  for i in 0 ..< 8: sgnCksumWire[i] = token[16 + i]
  for i in 0 ..< 8: encConfounder[i]= token[24 + i]

  # Decrypt SND_SEQ to recover the sequence number and direction byte.
  let kseq = deriveKseq(sessionKey, sgnCksumWire)
  let sndSeqPlain = rc4cipher.rc4(kseq, sndSeqEnc)
  let seq = (uint32(sndSeqPlain[0]) shl 24) or
            (uint32(sndSeqPlain[1]) shl 16) or
            (uint32(sndSeqPlain[2]) shl 8) or
             uint32(sndSeqPlain[3])
  # Direction marker: peer's view, so opposite of ours.
  let expectedDir: byte = if isInitiator: 0xFF'u8 else: 0x00'u8
  for i in 4 ..< 8:
    if sndSeqPlain[i] != expectedDir:
      return (seq: seq, ok: false)

  # Decrypt confounder + body using Kcrypt (peer's direction).
  let peerIsInitiator = not isInitiator
  let kcrypt = deriveKcrypt(sessionKey, seq, peerIsInitiator)
  var ctStream = newSeq[byte](Rc4ConfounderLen + dataLen)
  for i in 0 ..< Rc4ConfounderLen: ctStream[i] = encConfounder[i]
  for i in 0 ..< dataLen: ctStream[Rc4ConfounderLen + i] = data[i]
  let plainStream = rc4cipher.rc4(kcrypt, ctStream)

  var confounder: array[Rc4ConfounderLen, byte]
  for i in 0 ..< Rc4ConfounderLen: confounder[i] = plainStream[i]
  for i in 0 ..< dataLen: data[i] = plainStream[Rc4ConfounderLen + i]

  # Verify SGN_CKSUM = HMAC-MD5(Ksign, MD5(header || conf || plain)).
  let ksign = deriveKsign(sessionKey)
  let header = buildRc4Header(TokIdRc4Wrap, encrypt = true)
  var hashInput = newSeq[byte](8 + Rc4ConfounderLen + dataLen)
  for i in 0 ..< 8: hashInput[i] = header[i]
  for i in 0 ..< Rc4ConfounderLen: hashInput[8 + i] = confounder[i]
  for i in 0 ..< dataLen: hashInput[8 + Rc4ConfounderLen + i] = data[i]
  let inner = md5(hashInput)
  let cksumExpected = hmacMd5(ksign, inner)
  for i in 0 ..< 8:
    if cksumExpected[i] != sgnCksumWire[i]:
      return (seq: seq, ok: false)

  result = (seq: seq, ok: true)

# --- MIC token (sign-only, no confidentiality) --------------------

proc rc4GetMic*(sessionKey: openArray[byte]; message: openArray[byte];
                seq: uint32; isInitiator: bool): seq[byte] =
  ## RFC 4757 §7.3 MIC token. Same structure as Wrap but TOK_ID is
  ## different, SEAL_ALG = 0xFFFF, and there's no encrypted-data
  ## suffix. Confounder is still encrypted (under Kcrypt) and lives
  ## inside the 32-byte token.
  let ksign = deriveKsign(sessionKey)
  let header = buildRc4Header(TokIdRc4Mic, encrypt = false)

  var confounder: array[Rc4ConfounderLen, byte]
  let cb = randomBytes(Rc4ConfounderLen)
  for i in 0 ..< Rc4ConfounderLen: confounder[i] = cb[i]

  var hashInput = newSeq[byte](8 + Rc4ConfounderLen + message.len)
  for i in 0 ..< 8: hashInput[i] = header[i]
  for i in 0 ..< Rc4ConfounderLen: hashInput[8 + i] = confounder[i]
  for i in 0 ..< message.len: hashInput[8 + Rc4ConfounderLen + i] = message[i]
  let inner = md5(hashInput)
  let cksumFull = hmacMd5(ksign, inner)
  var sgnCksum: array[8, byte]
  for i in 0 ..< 8: sgnCksum[i] = cksumFull[i]

  let kseq = deriveKseq(sessionKey, sgnCksum)
  let seqBytes = beU32(seq)
  var sndSeqPlain: array[8, byte]
  for i in 0 ..< 4: sndSeqPlain[i] = seqBytes[i]
  let dirByte = if isInitiator: 0x00'u8 else: 0xFF'u8
  for i in 4 ..< 8: sndSeqPlain[i] = dirByte
  let sndSeqEnc = rc4cipher.rc4(kseq, sndSeqPlain)

  let kcrypt = deriveKcrypt(sessionKey, seq, isInitiator)
  let encConfounder = rc4cipher.rc4(kcrypt, confounder)

  result = newSeq[byte](Rc4TokenLen)
  for i in 0 ..< 8: result[i]      = header[i]
  for i in 0 ..< 8: result[8 + i]  = sndSeqEnc[i]
  for i in 0 ..< 8: result[16 + i] = sgnCksum[i]
  for i in 0 ..< 8: result[24 + i] = encConfounder[i]

proc rc4VerifyMic*(sessionKey: openArray[byte]; message: openArray[byte];
                   token: openArray[byte]; isInitiator: bool):
                   tuple[seq: uint32; ok: bool] =
  if token.len != Rc4TokenLen:
    return (seq: 0'u32, ok: false)
  if token[0] != TokIdRc4Mic[0] or token[1] != TokIdRc4Mic[1]:
    return (seq: 0'u32, ok: false)
  if token[4] != SealAlgNone[0] or token[5] != SealAlgNone[1]:
    return (seq: 0'u32, ok: false)

  var sndSeqEnc, sgnCksumWire, encConfounder: array[8, byte]
  for i in 0 ..< 8: sndSeqEnc[i]    = token[8 + i]
  for i in 0 ..< 8: sgnCksumWire[i] = token[16 + i]
  for i in 0 ..< 8: encConfounder[i]= token[24 + i]

  let kseq = deriveKseq(sessionKey, sgnCksumWire)
  let sndSeqPlain = rc4cipher.rc4(kseq, sndSeqEnc)
  let seq = (uint32(sndSeqPlain[0]) shl 24) or
            (uint32(sndSeqPlain[1]) shl 16) or
            (uint32(sndSeqPlain[2]) shl 8) or
             uint32(sndSeqPlain[3])
  let expectedDir: byte = if isInitiator: 0xFF'u8 else: 0x00'u8
  for i in 4 ..< 8:
    if sndSeqPlain[i] != expectedDir:
      return (seq: seq, ok: false)

  let peerIsInitiator = not isInitiator
  let kcrypt = deriveKcrypt(sessionKey, seq, peerIsInitiator)
  let confounder = rc4cipher.rc4(kcrypt, encConfounder)

  let ksign = deriveKsign(sessionKey)
  let header = buildRc4Header(TokIdRc4Mic, encrypt = false)
  var hashInput = newSeq[byte](8 + Rc4ConfounderLen + message.len)
  for i in 0 ..< 8: hashInput[i] = header[i]
  for i in 0 ..< Rc4ConfounderLen: hashInput[8 + i] = confounder[i]
  for i in 0 ..< message.len: hashInput[8 + Rc4ConfounderLen + i] = message[i]
  let inner = md5(hashInput)
  let cksumExpected = hmacMd5(ksign, inner)
  for i in 0 ..< 8:
    if cksumExpected[i] != sgnCksumWire[i]:
      return (seq: seq, ok: false)

  result = (seq: seq, ok: true)
