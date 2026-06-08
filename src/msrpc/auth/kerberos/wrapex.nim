## auth/kerberos/wrapex.nim — Microsoft's GSS_WrapEx for AES-CTS-
## HMAC-SHA1-96 (MS-KILE §3.4.5.4.1 + RFC 4121 §4.2 IOV layout).
##
## Plain GSS_Wrap produces one opaque blob with everything bundled.
## MS-RPC needs the bits distributed across separate buffers so the
## RPC PDU header stays in cleartext, the body gets encrypted in
## place (same length), and the integrity tag lands in the sec_trailer.
##
## For AES-CTS-HMAC-SHA1-96 the IOV layout is:
##
##   ┌───────────────────────────────────────────────────────────────┐
##   │ Header  [32 bytes]                                            │
##   │   [0..15]  cleartext RFC 4121 TokenHeader                     │
##   │   [16..31] first 16 bytes of AES-CTS output (== ciphertext of │
##   │            the random 16-byte confounder)                     │
##   ├───────────────────────────────────────────────────────────────┤
##   │ Data    [N bytes, same length as input plaintext]             │
##   │            middle of AES-CTS output (== ciphertext of plain)  │
##   ├───────────────────────────────────────────────────────────────┤
##   │ Trailer [28 bytes]                                            │
##   │   [0..15]  last 16 bytes of AES-CTS output (== ciphertext of  │
##   │            a duplicate of the cleartext TokenHeader)          │
##   │   [16..27] HMAC-SHA1-96(Ki, confounder || data || header)[:12]│
##   └───────────────────────────────────────────────────────────────┘
##
## On the wire in MS-RPC, the body bytes carry the Data buffer and the
## sec_trailer.auth_value carries Header || Trailer = 60 bytes.

import ../../crypto/[hmac_sha, rand]
import etype, gsswrap

const
  WrapExHeaderLen* = 32
  WrapExTrailerLen* = 28
  WrapExVerifierLen* = WrapExHeaderLen + WrapExTrailerLen   # 60

# --- encrypt -------------------------------------------------------

proc wrapExEncrypt*(baseKey: openArray[byte];
                    data: var openArray[byte];
                    dataLen: int;
                    sndSeq: uint64;
                    isInitiator: bool;
                    acceptorSubkey: bool = false):
                    array[WrapExVerifierLen, byte] =
  ## Encrypt ``data[0 ..< dataLen]`` in place (same length on output).
  ## Returns the 60-byte verifier (Header || Trailer) that goes into
  ## the RPC sec_trailer's auth_value. Bytes past ``dataLen`` in the
  ## buffer are untouched — this is how the RPC layer keeps a sec_trailer
  ## suffix in cleartext alongside the encrypted stub.
  doAssert dataLen >= 0 and dataLen <= data.len
  let usage =
    if isInitiator: KuInitiatorSeal else: KuAcceptorSeal
  let ke = deriveKey(baseKey, usageConstant(usage, 0xAA'u8))
  let ki = deriveKey(baseKey, usageConstant(usage, 0x55'u8))

  var flags: uint8 = FlagSealed
  if not isInitiator: flags = flags or FlagSentByAcceptor
  if acceptorSubkey: flags = flags or FlagAcceptorSubkey
  let tokenHdr = buildTokenHeader(TokIdWrap, flags, 0'u16, 0'u16, sndSeq)

  # Confounder is one cipher block of randomness.
  let confounder = randomBytes(16)

  # CTS input = confounder(16) || plaintext || copy-of-token-header(16)
  var ctsInput = newSeq[byte](16 + dataLen + 16)
  for i in 0 ..< 16: ctsInput[i] = confounder[i]
  for i in 0 ..< dataLen: ctsInput[16 + i] = data[i]
  for i in 0 ..< 16: ctsInput[16 + dataLen + i] = tokenHdr[i]

  # AES-CTS-CS3 is a same-length transform; output length == input.
  let cipherText = aesCtsEncrypt(ke, ctsInput)
  doAssert cipherText.len == ctsInput.len

  # RFC 3962 §6: HMAC keyed by Ki is computed over the PLAINTEXT
  # (including confounder), not the ciphertext.
  let hmac = hmacSha1(ki, ctsInput)

  # Distribute the AES-CTS output into Header (cleartext + ct[0..15]),
  # Data (ct[16..16+N-1] copied back in place), Trailer (ct[16+N..end]
  # || hmac[:12]).
  for i in 0 ..< 16: result[i] = tokenHdr[i]
  for i in 0 ..< 16: result[16 + i] = cipherText[i]
  for i in 0 ..< dataLen: data[i] = cipherText[16 + i]
  for i in 0 ..< 16:
    result[WrapExHeaderLen + i] = cipherText[16 + dataLen + i]
  for i in 0 ..< 12:
    result[WrapExHeaderLen + 16 + i] = hmac[i]

# --- decrypt -------------------------------------------------------

proc wrapExDecrypt*(baseKey: openArray[byte];
                    data: var openArray[byte];
                    dataLen: int;
                    verifier: openArray[byte];
                    isInitiator: bool):
                    tuple[sndSeq: uint64; ok: bool] =
  ## Inverse of wrapExEncrypt. ``verifier`` is the 60-byte auth_value
  ## (Header || Trailer). On success, ``data[0 ..< dataLen]`` is
  ## decrypted in place; bytes past dataLen are untouched.
  doAssert dataLen >= 0 and dataLen <= data.len
  if verifier.len != WrapExVerifierLen:
    return (sndSeq: 0'u64, ok: false)

  # Verify cleartext token header.
  if verifier[0] != TokIdWrap[0] or verifier[1] != TokIdWrap[1]:
    return (sndSeq: 0'u64, ok: false)
  let flags = verifier[2]
  if (flags and FlagSealed) == 0:
    return (sndSeq: 0'u64, ok: false)
  let sentByAcceptor = (flags and FlagSentByAcceptor) != 0
  # If I'm the initiator I expect the peer (acceptor) to set the flag,
  # and vice versa — reject when the polarity doesn't match.
  if sentByAcceptor != isInitiator:
    return (sndSeq: 0'u64, ok: false)

  let usage =
    if sentByAcceptor: KuAcceptorSeal else: KuInitiatorSeal
  let ke = deriveKey(baseKey, usageConstant(usage, 0xAA'u8))
  let ki = deriveKey(baseKey, usageConstant(usage, 0x55'u8))

  # Reassemble the AES-CTS ciphertext in natural order:
  #   verifier[16..31] (encrypted confounder)
  #   data[0..N-1]     (encrypted body)
  #   verifier[32..47] (encrypted trail header) -- = WrapExHeaderLen..WrapExHeaderLen+16
  var cipherText = newSeq[byte](16 + dataLen + 16)
  for i in 0 ..< 16: cipherText[i] = verifier[16 + i]
  for i in 0 ..< dataLen: cipherText[16 + i] = data[i]
  for i in 0 ..< 16:
    cipherText[16 + dataLen + i] = verifier[WrapExHeaderLen + i]

  let plain = aesCtsDecrypt(ke, cipherText)
  if plain.len != cipherText.len:
    return (sndSeq: 0'u64, ok: false)

  # The trailing 16 bytes of plain must match the cleartext header at
  # verifier[0..15] — that's what proves we have the right key.
  for i in 0 ..< 16:
    if plain[16 + dataLen + i] != verifier[i]:
      return (sndSeq: 0'u64, ok: false)

  # Verify HMAC over (confounder || data_plain || trail_hdr) == plain.
  let expectedHmac = hmacSha1(ki, plain)
  var hmacOk = true
  for i in 0 ..< 12:
    if expectedHmac[i] != verifier[WrapExHeaderLen + 16 + i]:
      hmacOk = false
  if not hmacOk:
    return (sndSeq: 0'u64, ok: false)

  # Copy the decrypted body bytes back into the caller's data buffer.
  for i in 0 ..< dataLen: data[i] = plain[16 + i]

  result.sndSeq = parseSeq(verifier)
  result.ok = true
