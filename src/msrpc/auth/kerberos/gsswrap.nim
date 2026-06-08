## auth/kerberos/gsswrap.nim — RFC 4121 GSS_Wrap / GSS_Unwrap and
## GSS_GetMIC / GSS_VerifyMIC over AES-CTS-HMAC-SHA1-96.
##
## Wire layout (RFC 4121 §4.2 — Wrap with confidentiality):
##
##   ┌──────────────────────────────────────────────────────────────┐
##   │ TokenHeader (16 bytes, cleartext)                            │
##   │   0..1   TOK_ID = 0x05 0x04                                  │
##   │   2      Flags  (bit 0 SentByAcceptor, 1 Sealed, 2 Subkey)   │
##   │   3      Filler = 0xFF                                       │
##   │   4..5   EC                                                  │
##   │   6..7   RRC                                                 │
##   │   8..15  Sequence number, big-endian                         │
##   ├──────────────────────────────────────────────────────────────┤
##   │ Encrypted blob = AES-CTS-HMAC-SHA1-96(                       │
##   │     Ke, plaintext || TokenHeader                             │
##   │   ) with the integrity tag built in                          │
##   └──────────────────────────────────────────────────────────────┘
##
## The encryption profile prepends a 16-byte confounder internally and
## appends a 12-byte HMAC, so the encrypted blob is always
## (plaintext.len + 16 + 16 + 12) = plaintext.len + 44 bytes.
##
## For MIC tokens (TOK_ID 0x04 0x04, integrity only) we use the
## profile's checksum primitive (HMAC-SHA1-96 keyed by Kc).
##
## Key-usage numbers come from RFC 4121 §2:
##   22 = KG_USAGE_ACCEPTOR_SEAL   (server → client confidentiality)
##   23 = KG_USAGE_ACCEPTOR_SIGN   (server → client integrity-only)
##   24 = KG_USAGE_INITIATOR_SEAL  (client → server confidentiality)
##   25 = KG_USAGE_INITIATOR_SIGN  (client → server integrity-only)

import etype, aes as krbAes

const
  TokIdWrap* = [0x05'u8, 0x04]
  TokIdMic*  = [0x04'u8, 0x04]

  KuAcceptorSeal*  = 22'u32
  KuAcceptorSign*  = 23'u32
  KuInitiatorSeal* = 24'u32
  KuInitiatorSign* = 25'u32

  FlagSentByAcceptor* = 0x01'u8
  FlagSealed*         = 0x02'u8
  FlagAcceptorSubkey* = 0x04'u8

  TokenHeaderLen* = 16

# --- header (cleartext, 16 bytes) ---------------------------------

proc buildTokenHeader*(tokId: openArray[byte];
                       flags: uint8; ec, rrc: uint16; sndSeq: uint64):
                       array[16, byte] =
  result[0] = tokId[0]
  result[1] = tokId[1]
  result[2] = flags
  result[3] = 0xFF'u8
  result[4] = byte((ec shr 8) and 0xff)
  result[5] = byte(ec and 0xff)
  result[6] = byte((rrc shr 8) and 0xff)
  result[7] = byte(rrc and 0xff)
  for i in 0 ..< 8:
    result[8 + i] = byte((sndSeq shr ((7 - i) * 8)) and 0xff)

proc parseSeq*(header: openArray[byte]): uint64 =
  doAssert header.len >= 16
  for i in 0 ..< 8:
    result = (result shl 8) or uint64(header[8 + i])

# --- Wrap with confidentiality (sealed) ---------------------------

proc gssWrap*(baseKey: openArray[byte];
              plaintext: openArray[byte];
              sndSeq: uint64;
              isInitiator: bool;
              acceptorSubkey: bool = false): seq[byte] =
  ## Returns the full GSS Wrap token. ``isInitiator`` is true on the
  ## client (the side that sent the initial AP-REQ); false on the
  ## server. The key-usage number is picked accordingly.
  let usage =
    if isInitiator: KuInitiatorSeal else: KuAcceptorSeal
  var flags: uint8 = FlagSealed
  if not isInitiator: flags = flags or FlagSentByAcceptor
  if acceptorSubkey: flags = flags or FlagAcceptorSubkey
  let header = buildTokenHeader(TokIdWrap, flags, 0'u16, 0'u16, sndSeq)
  # to-encrypt = plaintext || cleartext header
  var payload = newSeq[byte](plaintext.len + TokenHeaderLen)
  for i in 0 ..< plaintext.len: payload[i] = plaintext[i]
  for i in 0 ..< TokenHeaderLen:
    payload[plaintext.len + i] = header[i]
  let cipher = krbAes.aesEncrypt(baseKey, payload, usage)
  # Token = cleartext header || encrypted blob
  result = newSeq[byte](TokenHeaderLen + cipher.len)
  for i in 0 ..< TokenHeaderLen: result[i] = header[i]
  for i in 0 ..< cipher.len: result[TokenHeaderLen + i] = cipher[i]

proc gssUnwrap*(baseKey: openArray[byte];
                token: openArray[byte];
                isInitiator: bool):
                tuple[plaintext: seq[byte]; sndSeq: uint64; ok: bool] =
  ## Verify+decrypt a Wrap token. ``isInitiator`` is true on the side
  ## doing the unwrapping (we'll use the *peer's* usage number).
  if token.len < TokenHeaderLen + krbAes.ConfounderLen + krbAes.HmacLen + TokenHeaderLen:
    return (plaintext: @[], sndSeq: 0'u64, ok: false)
  if token[0] != TokIdWrap[0] or token[1] != TokIdWrap[1]:
    return (plaintext: @[], sndSeq: 0'u64, ok: false)
  let flags = token[2]
  if (flags and FlagSealed) == 0:
    return (plaintext: @[], sndSeq: 0'u64, ok: false)
  let sentByAcceptor = (flags and FlagSentByAcceptor) != 0
  # When *we* are the initiator, we expect messages sent by the acceptor.
  if sentByAcceptor != isInitiator:
    return (plaintext: @[], sndSeq: 0'u64, ok: false)
  let usage =
    if sentByAcceptor: KuAcceptorSeal else: KuInitiatorSeal
  let seq = parseSeq(token)
  let cipher = token[TokenHeaderLen ..< token.len]
  let (plain, ok) = krbAes.aesDecrypt(baseKey, cipher, usage)
  if not ok:
    return (plaintext: @[], sndSeq: seq, ok: false)
  # Decrypted plain ends with the same TokenHeader that arrived in
  # cleartext — verify it matches (modulo the flags byte: GSS spec
  # zeroes the SentByAcceptor flag when verifying because some peers
  # treat it as informational).
  if plain.len < TokenHeaderLen:
    return (plaintext: @[], sndSeq: seq, ok: false)
  let bodyLen = plain.len - TokenHeaderLen
  for i in 0 ..< TokenHeaderLen:
    if plain[bodyLen + i] != token[i]:
      return (plaintext: @[], sndSeq: seq, ok: false)
  result.plaintext = plain[0 ..< bodyLen]
  result.sndSeq = seq
  result.ok = true

# --- MIC (integrity-only, no confidentiality) ---------------------

proc gssGetMic*(baseKey: openArray[byte];
                message: openArray[byte];
                sndSeq: uint64;
                isInitiator: bool;
                acceptorSubkey: bool = false): seq[byte] =
  ## Produce a GSS MIC token over ``message``. The token is:
  ##   TokenHeader(16) || HMAC-SHA1-96(Kc, message || TokenHeader)
  let usage =
    if isInitiator: KuInitiatorSign else: KuAcceptorSign
  var flags: uint8 = 0
  if not isInitiator: flags = flags or FlagSentByAcceptor
  if acceptorSubkey: flags = flags or FlagAcceptorSubkey
  let header = buildTokenHeader(TokIdMic, flags, 0'u16, 0'u16, sndSeq)
  # Kc = DK(K, usage || 0x99)
  let kc = deriveKey(baseKey, usageConstant(usage, 0x99'u8))
  var msg = newSeq[byte](message.len + TokenHeaderLen)
  for i in 0 ..< message.len: msg[i] = message[i]
  for i in 0 ..< TokenHeaderLen: msg[message.len + i] = header[i]
  let mac = hmacSha1Truncated(kc, msg)
  result = newSeq[byte](TokenHeaderLen + 12)
  for i in 0 ..< TokenHeaderLen: result[i] = header[i]
  for i in 0 ..< 12: result[TokenHeaderLen + i] = mac[i]

proc gssVerifyMic*(baseKey: openArray[byte];
                    message: openArray[byte];
                    token: openArray[byte];
                    isInitiator: bool):
                    tuple[sndSeq: uint64; ok: bool] =
  if token.len != TokenHeaderLen + 12:
    return (sndSeq: 0'u64, ok: false)
  if token[0] != TokIdMic[0] or token[1] != TokIdMic[1]:
    return (sndSeq: 0'u64, ok: false)
  let sentByAcceptor = (token[2] and FlagSentByAcceptor) != 0
  if sentByAcceptor != isInitiator:
    return (sndSeq: 0'u64, ok: false)
  let usage =
    if sentByAcceptor: KuAcceptorSign else: KuInitiatorSign
  let kc = deriveKey(baseKey, usageConstant(usage, 0x99'u8))
  var msg = newSeq[byte](message.len + TokenHeaderLen)
  for i in 0 ..< message.len: msg[i] = message[i]
  for i in 0 ..< TokenHeaderLen: msg[message.len + i] = token[i]
  let expected = hmacSha1Truncated(kc, msg)
  var ok = true
  for i in 0 ..< 12:
    if expected[i] != token[TokenHeaderLen + i]: ok = false
  result.sndSeq = parseSeq(token)
  result.ok = ok
