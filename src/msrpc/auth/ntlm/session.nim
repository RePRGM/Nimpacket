## ntlm/session.nim — NTLMv2 session keys, NtChallengeResponse, and the
## SEAL/SIGN/UNSEAL primitives.
##
## Spec references: MS-NLMP §3.3.2 (NtChallengeResponse), §3.4.5.2
## (SignKey/SealKey derivation), §3.4.4.1 (extended-session-security
## sign/seal). The four signing/sealing magic constants come from
## §3.4.5.2 verbatim, including the trailing NUL.

import ../../common/[buffers, endian]
import ../../crypto/[md5, hmac, rc4]

# --- magic constants (MS-NLMP §3.4.5.2) ---------------------------------

const
  ClientSignMagic* = "session key to client-to-server signing key magic constant\0"
  ServerSignMagic* = "session key to server-to-client signing key magic constant\0"
  ClientSealMagic* = "session key to client-to-server sealing key magic constant\0"
  ServerSealMagic* = "session key to server-to-client sealing key magic constant\0"

proc magicBytes(s: string): seq[byte] =
  result = newSeq[byte](s.len)
  for i, ch in s: result[i] = byte(ch.ord)

# --- key derivation ------------------------------------------------------

proc deriveSignKey*(exportedSessionKey: openArray[byte]; magic: string): array[16, byte] =
  ## MD5( ExportedSessionKey || magic )
  var inp = newSeq[byte](exportedSessionKey.len + magic.len)
  for i in 0 ..< exportedSessionKey.len: inp[i] = exportedSessionKey[i]
  for i, ch in magic: inp[exportedSessionKey.len + i] = byte(ch.ord)
  result = md5(inp)

proc deriveSealKey*(exportedSessionKey: openArray[byte]; magic: string): array[16, byte] =
  ## Identical algorithm to deriveSignKey — kept distinct for spec clarity.
  deriveSignKey(exportedSessionKey, magic)

# --- NtChallengeResponse + SessionBaseKey (MS-NLMP §3.3.2) --------------

type
  NtV2Response* = object
    ntProofStr*: array[16, byte]
    response*: seq[byte]          ## NTProofStr || temp
    sessionBaseKey*: array[16, byte]

proc computeNtV2Response*(
    responseKeyNT: openArray[byte];
    serverChallenge: openArray[byte];
    clientChallenge: openArray[byte];
    timestamp: uint64;
    targetInfo: openArray[byte]
   ): NtV2Response =
  ## Build the NTLMv2 response and session base key.
  ##
  ## * ``responseKeyNT`` — output of ``NTOWFv2(password, user, domain)``
  ## * ``serverChallenge`` / ``clientChallenge`` — 8 bytes each
  ## * ``timestamp`` — Windows FILETIME (100ns since 1601-01-01 UTC)
  ## * ``targetInfo`` — raw AV_PAIR blob from the CHALLENGE message
  doAssert serverChallenge.len == 8
  doAssert clientChallenge.len == 8

  # temp = Responserversion(1) || HiResponserversion(1) || Z(6) ||
  #        Timestamp(8) || ClientChallenge(8) || Z(4) || TargetInfo || Z(4)
  let b = newBuffer()
  b.writeByte(0x01)                 # Responserversion
  b.writeByte(0x01)                 # HiResponserversion
  for _ in 0 ..< 6: b.writeByte(0)  # Reserved
  b.writeU64LE(timestamp)
  for x in clientChallenge: b.writeByte(x)
  for _ in 0 ..< 4: b.writeByte(0)  # Reserved
  b.writeBytes(targetInfo)
  for _ in 0 ..< 4: b.writeByte(0)  # trailing Z(4)
  let temp = b.consumed

  # NTProofStr = HMAC_MD5(ResponseKeyNT, ServerChallenge || temp)
  var proofInput = newSeq[byte](8 + temp.len)
  for i in 0 ..< 8: proofInput[i] = serverChallenge[i]
  for i in 0 ..< temp.len: proofInput[8 + i] = temp[i]
  result.ntProofStr = hmacMd5(responseKeyNT, proofInput)

  result.response = newSeq[byte](16 + temp.len)
  for i in 0 ..< 16: result.response[i] = result.ntProofStr[i]
  for i in 0 ..< temp.len: result.response[16 + i] = temp[i]

  # SessionBaseKey = HMAC_MD5(ResponseKeyNT, NTProofStr)
  result.sessionBaseKey = hmacMd5(responseKeyNT, result.ntProofStr)

# --- LmV2 response (MS-NLMP §3.3.2) -------------------------------------

proc computeLmV2Response*(
    responseKeyLM: openArray[byte];      ## LMOWFv2 = NTOWFv2
    serverChallenge: openArray[byte];
    clientChallenge: openArray[byte]
   ): seq[byte] =
  doAssert serverChallenge.len == 8
  doAssert clientChallenge.len == 8
  var msg = newSeq[byte](16)
  for i in 0 ..< 8: msg[i] = serverChallenge[i]
  for i in 0 ..< 8: msg[8 + i] = clientChallenge[i]
  let hmac = hmacMd5(responseKeyLM, msg)
  result = newSeq[byte](24)
  for i in 0 ..< 16: result[i] = hmac[i]
  for i in 0 ..< 8: result[16 + i] = clientChallenge[i]

# --- session-level state -----------------------------------------------

type
  NtlmSession* = ref object
    exportedSessionKey*: array[16, byte]
    clientSigningKey*: array[16, byte]
    serverSigningKey*: array[16, byte]
    clientSealingKey*: array[16, byte]
    serverSealingKey*: array[16, byte]
    clientSeal*: Rc4Ctx     ## RC4 stream for outbound sealing
    serverSeal*: Rc4Ctx     ## RC4 stream for inbound unsealing
    clientSeq*: uint32
    serverSeq*: uint32

proc initSession*(s: NtlmSession; exportedSessionKey: openArray[byte]) =
  doAssert exportedSessionKey.len == 16
  for i in 0 ..< 16: s.exportedSessionKey[i] = exportedSessionKey[i]
  s.clientSigningKey = deriveSignKey(exportedSessionKey, ClientSignMagic)
  s.serverSigningKey = deriveSignKey(exportedSessionKey, ServerSignMagic)
  s.clientSealingKey = deriveSealKey(exportedSessionKey, ClientSealMagic)
  s.serverSealingKey = deriveSealKey(exportedSessionKey, ServerSealMagic)
  s.clientSeal.initRc4(s.clientSealingKey)
  s.serverSeal.initRc4(s.serverSealingKey)
  s.clientSeq = 0
  s.serverSeq = 0

proc newNtlmSession*(exportedSessionKey: openArray[byte]): NtlmSession =
  result = NtlmSession()
  initSession(result, exportedSessionKey)

# --- sign / seal (extended session security, MS-NLMP §3.4.4.1) ----------

const NtlmSignVersion*: array[4, byte] = [0x01'u8, 0, 0, 0]

proc computeSignature(signKey: openArray[byte]; sealCtx: var Rc4Ctx;
                      message: openArray[byte]; seqNum: uint32;
                      doSeal: bool): array[16, byte] =
  ## Build the 16-byte ESS signature over ``message`` at sequence
  ## ``seqNum``. When ``doSeal`` is set, the truncated HMAC is RC4'd
  ## under ``sealCtx`` (which is the same stream used to encrypt the
  ## message body, advancing it).
  var inp = newSeq[byte](4 + message.len)
  inp[0] = byte(seqNum and 0xff'u32)
  inp[1] = byte((seqNum shr 8) and 0xff'u32)
  inp[2] = byte((seqNum shr 16) and 0xff'u32)
  inp[3] = byte((seqNum shr 24) and 0xff'u32)
  for i in 0 ..< message.len: inp[4 + i] = message[i]
  let h = hmacMd5(signKey, inp)

  var sig8: array[8, byte]
  for i in 0 ..< 8: sig8[i] = h[i]
  if doSeal:
    sealCtx.apply(sig8)

  for i in 0 ..< 4: result[i] = NtlmSignVersion[i]
  for i in 0 ..< 8: result[4 + i] = sig8[i]
  result[12] = byte(seqNum and 0xff'u32)
  result[13] = byte((seqNum shr 8) and 0xff'u32)
  result[14] = byte((seqNum shr 16) and 0xff'u32)
  result[15] = byte((seqNum shr 24) and 0xff'u32)

proc signOutgoing*(s: NtlmSession; message: openArray[byte];
                   doSeal = false): array[16, byte] =
  ## Sign an outbound (client→server) message; consumes one client seq#.
  result = computeSignature(s.clientSigningKey, s.clientSeal, message,
                            s.clientSeq, doSeal)
  inc s.clientSeq

proc sealOutgoing*(s: NtlmSession; message: var openArray[byte]): array[16, byte] =
  ## Encrypt ``message`` in place under the client sealing key and
  ## return the signature over the *plaintext* (signature itself is
  ## RC4'd by the same advancing stream).
  let sig = computeSignature(s.clientSigningKey, s.clientSeal, message,
                             s.clientSeq, doSeal = true)
  s.clientSeal.apply(message)
  inc s.clientSeq
  result = sig

proc verifyIncoming*(s: NtlmSession; message: openArray[byte];
                     signature: openArray[byte]): bool =
  ## Verify a signature on an inbound (server→client) signed-only
  ## message; consumes one server seq#.
  doAssert signature.len == 16
  let expected = computeSignature(s.serverSigningKey, s.serverSeal, message,
                                  s.serverSeq, doSeal = false)
  inc s.serverSeq
  for i in 0 ..< 16:
    if signature[i] != expected[i]: return false
  return true

proc signSealPartial*(s: NtlmSession; data: var openArray[byte];
                       sealLen: int; forClient = true): array[16, byte] =
  ## RPC-flavoured signing for messages where only a prefix is sealed
  ## (encrypted) while the suffix is sent in plaintext. The signature
  ## covers the entire ``data`` (plaintext) before encryption.
  ##
  ## In DCE-RPC: ``data`` = stub || pad || sec_trailer, and ``sealLen``
  ## = stub.len + pad.len (the sec_trailer goes out in plaintext but is
  ## still HMAC'd as part of the signed bytes).
  doAssert sealLen >= 0 and sealLen <= data.len
  let signKey = if forClient: s.clientSigningKey else: s.serverSigningKey
  let sealCtx = if forClient: addr s.clientSeal else: addr s.serverSeal
  let seq = if forClient: s.clientSeq else: s.serverSeq

  # 1. HMAC over (seq || plaintext data)
  var inp = newSeq[byte](4 + data.len)
  inp[0] = byte(seq and 0xff'u32)
  inp[1] = byte((seq shr 8) and 0xff'u32)
  inp[2] = byte((seq shr 16) and 0xff'u32)
  inp[3] = byte((seq shr 24) and 0xff'u32)
  for i in 0 ..< data.len: inp[4 + i] = data[i]
  let h = hmacMd5(signKey, inp)

  # 2. RC4 the 8 sig bytes (advance stream by 8)
  var sig8: array[8, byte]
  for i in 0 ..< 8: sig8[i] = h[i]
  sealCtx[].apply(sig8)

  # 3. RC4 the sealed prefix of data (advance stream by sealLen)
  if sealLen > 0:
    var prefix = newSeq[byte](sealLen)
    for i in 0 ..< sealLen: prefix[i] = data[i]
    sealCtx[].apply(prefix)
    for i in 0 ..< sealLen: data[i] = prefix[i]

  # 4. Assemble verifier
  for i in 0 ..< 4: result[i] = NtlmSignVersion[i]
  for i in 0 ..< 8: result[4 + i] = sig8[i]
  result[12] = byte(seq and 0xff'u32)
  result[13] = byte((seq shr 8) and 0xff'u32)
  result[14] = byte((seq shr 16) and 0xff'u32)
  result[15] = byte((seq shr 24) and 0xff'u32)

  if forClient: inc s.clientSeq else: inc s.serverSeq

proc unsealVerifyPartial*(s: NtlmSession; data: var openArray[byte];
                           sealLen: int; signature: openArray[byte];
                           forClient = false): bool =
  ## Inverse of ``signSealPartial``: decrypts the prefix and verifies
  ## the signature was computed over the plaintext form of ``data``.
  doAssert signature.len == 16
  doAssert sealLen >= 0 and sealLen <= data.len
  if signature[0] != NtlmSignVersion[0] or signature[1] != NtlmSignVersion[1] or
     signature[2] != NtlmSignVersion[2] or signature[3] != NtlmSignVersion[3]:
    return false
  let signKey = if forClient: s.clientSigningKey else: s.serverSigningKey
  let sealCtx = if forClient: addr s.clientSeal else: addr s.serverSeal
  let seq = if forClient: s.clientSeq else: s.serverSeq

  # 1. Decrypt embedded sig bytes (RC4 advances by 8)
  var rawSig: array[8, byte]
  for i in 0 ..< 8: rawSig[i] = signature[4 + i]
  sealCtx[].apply(rawSig)

  # 2. Decrypt the sealed prefix (RC4 advances by sealLen)
  if sealLen > 0:
    var prefix = newSeq[byte](sealLen)
    for i in 0 ..< sealLen: prefix[i] = data[i]
    sealCtx[].apply(prefix)
    for i in 0 ..< sealLen: data[i] = prefix[i]

  # 3. Re-HMAC over plaintext data
  var inp = newSeq[byte](4 + data.len)
  inp[0] = byte(seq and 0xff'u32)
  inp[1] = byte((seq shr 8) and 0xff'u32)
  inp[2] = byte((seq shr 16) and 0xff'u32)
  inp[3] = byte((seq shr 24) and 0xff'u32)
  for i in 0 ..< data.len: inp[4 + i] = data[i]
  let h = hmacMd5(signKey, inp)

  let seqOk =
    signature[12] == byte(seq and 0xff'u32) and
    signature[13] == byte((seq shr 8) and 0xff'u32) and
    signature[14] == byte((seq shr 16) and 0xff'u32) and
    signature[15] == byte((seq shr 24) and 0xff'u32)
  if forClient: inc s.clientSeq else: inc s.serverSeq
  if not seqOk: return false
  for i in 0 ..< 8:
    if rawSig[i] != h[i]: return false
  return true

proc unsealIncoming*(s: NtlmSession; ciphertext: var openArray[byte];
                     signature: openArray[byte]): bool =
  ## Decrypt ``ciphertext`` in place and verify the signature.
  ##
  ## Stream order matches the sender (sealOutgoing): the 8 truncated
  ## HMAC bytes are RC4'd first, then the message body. To verify, we
  ## "decrypt" the embedded sig bytes first (advancing the stream by 8)
  ## then decrypt the body.
  doAssert signature.len == 16
  if signature[0] != NtlmSignVersion[0] or signature[1] != NtlmSignVersion[1] or
     signature[2] != NtlmSignVersion[2] or signature[3] != NtlmSignVersion[3]:
    return false

  var rawSig: array[8, byte]
  for i in 0 ..< 8: rawSig[i] = signature[4 + i]
  s.serverSeal.apply(rawSig)
  s.serverSeal.apply(ciphertext)

  var inp = newSeq[byte](4 + ciphertext.len)
  inp[0] = byte(s.serverSeq and 0xff'u32)
  inp[1] = byte((s.serverSeq shr 8) and 0xff'u32)
  inp[2] = byte((s.serverSeq shr 16) and 0xff'u32)
  inp[3] = byte((s.serverSeq shr 24) and 0xff'u32)
  for i in 0 ..< ciphertext.len: inp[4 + i] = ciphertext[i]
  let h = hmacMd5(s.serverSigningKey, inp)

  let seqOk =
    signature[12] == byte(s.serverSeq and 0xff'u32) and
    signature[13] == byte((s.serverSeq shr 8) and 0xff'u32) and
    signature[14] == byte((s.serverSeq shr 16) and 0xff'u32) and
    signature[15] == byte((s.serverSeq shr 24) and 0xff'u32)
  inc s.serverSeq
  if not seqOk: return false
  for i in 0 ..< 8:
    if rawSig[i] != h[i]: return false
  return true
