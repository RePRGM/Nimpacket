## auth/kerberos/rc4.nim — RFC 4757 RC4-HMAC ETYPE (23).
##
## Still common in AD environments for accounts that haven't been
## set to AES-only. The wire form is:
##
##   ciphertext = HMAC(K2, confounder || plaintext) ||
##                RC4(K3, confounder || plaintext)
##
## where:
##   K  = NT hash = MD4(UTF-16LE(password))      -- the base key
##   K1 = HMAC-MD5(K,  little-endian-u32(usage))  -- per-usage subkey
##   K2 = K1                                       -- integrity key
##   K3 = HMAC-MD5(K1, checksum)                  -- encryption key
##
## ``usage`` is a 32-bit Kerberos "key usage number" naming the
## context the encryption is used in (e.g. 1 = AS-REQ PA-ENC-TIMESTAMP,
## 8 = AS-REP encrypted part with usage-from-key, etc.).

import ../../common/unicode
import ../../crypto/[md4, hmac, rc4, rand]

const EtypeRc4Hmac* = 23'u32

# --- string-to-key -------------------------------------------------

proc rc4HmacStringToKey*(password: string): array[16, byte] =
  ## RFC 4757 §3 says the RC4-HMAC key is just the NT hash of the
  ## password — the same 16-byte value NTLM has been using since
  ## forever.
  result = md4(toUtf16Bytes(password))

# --- key derivation per usage --------------------------------------

proc deriveK1*(baseKey: openArray[byte]; usage: uint32): array[16, byte] =
  ## K1 = HMAC-MD5(K, little-endian-u32(usage))
  var usageBytes: array[4, byte]
  usageBytes[0] = byte(usage and 0xff'u32)
  usageBytes[1] = byte((usage shr 8) and 0xff'u32)
  usageBytes[2] = byte((usage shr 16) and 0xff'u32)
  usageBytes[3] = byte((usage shr 24) and 0xff'u32)
  result = hmacMd5(baseKey, usageBytes)

# --- encrypt -------------------------------------------------------

proc rc4HmacEncrypt*(baseKey: openArray[byte]; plaintext: openArray[byte];
                    usage: uint32): seq[byte] =
  ## RFC 4757 §3 encryption. Returns checksum(16) || rc4(plain) of
  ## the same total length as ``plaintext.len + 24``.
  let k1 = deriveK1(baseKey, usage)
  # Confounder is 8 random bytes.
  var confounder = newSeq[byte](8)
  let cb = randomBytes(8)
  for i in 0 ..< 8: confounder[i] = cb[i]
  var msg = newSeq[byte](8 + plaintext.len)
  for i in 0 ..< 8: msg[i] = confounder[i]
  for i in 0 ..< plaintext.len: msg[8 + i] = plaintext[i]

  let checksum = hmacMd5(k1, msg)
  let k3 = hmacMd5(k1, checksum)
  let encrypted = rc4(k3, msg)

  result = newSeq[byte](16 + encrypted.len)
  for i in 0 ..< 16: result[i] = checksum[i]
  for i in 0 ..< encrypted.len: result[16 + i] = encrypted[i]

# --- decrypt -------------------------------------------------------

proc rc4HmacDecrypt*(baseKey: openArray[byte]; ciphertext: openArray[byte];
                    usage: uint32): tuple[plaintext: seq[byte]; ok: bool] =
  ## RFC 4757 §3 decryption with checksum verification.
  if ciphertext.len < 24:
    return (plaintext: @[], ok: false)
  let k1 = deriveK1(baseKey, usage)
  var checksum = newSeq[byte](16)
  for i in 0 ..< 16: checksum[i] = ciphertext[i]
  let k3 = hmacMd5(k1, checksum)
  let encrypted = ciphertext[16 ..< ciphertext.len]
  let msg = rc4(k3, encrypted)
  let expected = hmacMd5(k1, msg)
  var ok = true
  for i in 0 ..< 16:
    if expected[i] != checksum[i]:
      ok = false
  if not ok:
    return (plaintext: @[], ok: false)
  # First 8 bytes were the confounder; strip them.
  result.plaintext = msg[8 ..< msg.len]
  result.ok = true
