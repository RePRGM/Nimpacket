## auth/kerberos/aes.nim — RFC 3962 §3 AES-CTS-HMAC-SHA1-96 profile.
##
## Encryption format on the wire (the "EncryptedData.cipher" payload):
##
##   confounder(16) || AES-CTS(Ke, confounder || plaintext) || HMAC-SHA1-96(Ki, …)
##
## Wait — actually the form is:
##
##   AES-CTS-Encrypt(Ke, confounder(16) || plaintext) || HMAC-SHA1-96(Ki, confounder || plaintext)[0..11]
##
## where:
##   Ke = DK(base-key, BE(usage) || 0xAA)   -- encryption subkey
##   Ki = DK(base-key, BE(usage) || 0x55)   -- integrity subkey
##   confounder = 16 random bytes (1 block) prepended to the plaintext
##
## Decryption reverses the order: split off the trailing HMAC, decrypt
## the body with Ke, strip the leading 16-byte confounder, then verify
## the HMAC over (confounder || plaintext).

import ../../crypto/rand
import etype

const ConfounderLen* = 16
const HmacLen* = 12        # SHA-1-96 truncated to 12 bytes

proc aesEncrypt*(baseKey, plaintext: openArray[byte];
                 usage: uint32; confounder: openArray[byte] = @[]):
                 seq[byte] =
  ## Encrypt under the AES-CTS-HMAC-SHA1-96 profile. ``confounder`` is
  ## optional — when empty (default) 16 random bytes are used.
  let ke = deriveKey(baseKey, usageConstant(usage, 0xAA'u8))
  let ki = deriveKey(baseKey, usageConstant(usage, 0x55'u8))
  var cf = newSeq[byte](ConfounderLen)
  if confounder.len == ConfounderLen:
    for i in 0 ..< ConfounderLen: cf[i] = confounder[i]
  else:
    let r = randomBytes(ConfounderLen)
    for i in 0 ..< ConfounderLen: cf[i] = r[i]
  var basicPt = newSeq[byte](ConfounderLen + plaintext.len)
  for i in 0 ..< ConfounderLen: basicPt[i] = cf[i]
  for i in 0 ..< plaintext.len: basicPt[ConfounderLen + i] = plaintext[i]
  let ct = aesCtsEncrypt(ke, basicPt)
  let mac = hmacSha1Truncated(ki, basicPt)
  result = newSeq[byte](ct.len + HmacLen)
  for i in 0 ..< ct.len: result[i] = ct[i]
  for i in 0 ..< HmacLen: result[ct.len + i] = mac[i]

proc aesDecrypt*(baseKey, ciphertext: openArray[byte]; usage: uint32):
                 tuple[plaintext: seq[byte]; ok: bool] =
  ## Verify+decrypt. Returns (plaintext_with_confounder_stripped, ok).
  if ciphertext.len < ConfounderLen + HmacLen:
    return (plaintext: @[], ok: false)
  let ke = deriveKey(baseKey, usageConstant(usage, 0xAA'u8))
  let ki = deriveKey(baseKey, usageConstant(usage, 0x55'u8))
  let ctOnly = ciphertext[0 ..< ciphertext.len - HmacLen]
  let macWire = ciphertext[ciphertext.len - HmacLen ..< ciphertext.len]
  let basicPt = aesCtsDecrypt(ke, ctOnly)
  let macComputed = hmacSha1Truncated(ki, basicPt)
  var ok = true
  for i in 0 ..< HmacLen:
    if byte(macComputed[i]) != macWire[i]: ok = false
  if not ok:
    return (plaintext: @[], ok: false)
  result.plaintext = basicPt[ConfounderLen ..< basicPt.len]
  result.ok = true
