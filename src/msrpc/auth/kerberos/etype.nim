## auth/kerberos/etype.nim — Kerberos encryption types.
##
## We implement the modern AES variants:
##   * etypeAes128CtsHmacSha1_96   = 17  (RFC 3962)
##   * etypeAes256CtsHmacSha1_96   = 18  (RFC 3962)
##
## RC4-HMAC (23) is legacy and is no longer recommended; we skip it
## by default but the constant is exported for compatibility flags.
##
## The "CTS" (ciphertext-stealing) mode wraps AES-CBC such that
## arbitrary-length plaintext doesn't need padding. We follow
## RFC 3962 §5: AES-CBC with ciphertext stealing for the last two
## blocks; for inputs ≤ 16 bytes a single AES block is used.

import ../../crypto/[aes, hmac_sha, kdf]
import nfold

const
  EtypeAes128*  = 17'u32
  EtypeAes256*  = 18'u32
  EtypeRc4Hmac* = 23'u32

const Aes128KeyLen = 16
const Aes256KeyLen = 32

# --- AES-CBC core --------------------------------------------------

proc aesCbcEncryptBlocks(key: openArray[byte]; iv: array[16, byte];
                         plaintext: openArray[byte]): seq[byte] =
  ## Plain AES-CBC over a multiple-of-16 plaintext; returns the
  ## ciphertext blocks (no padding, no MAC).
  doAssert plaintext.len mod 16 == 0
  var ctx128: Aes128Ctx
  var ctx256: Aes256Ctx
  let is128 = key.len == 16
  if is128: ctx128.initAes128(key) else: ctx256.initAes256(key)
  result = newSeq[byte](plaintext.len)
  var prev = iv
  var i = 0
  while i < plaintext.len:
    var blk: array[16, byte]
    for k in 0 ..< 16: blk[k] = plaintext[i + k] xor prev[k]
    let enc = if is128: ctx128.encryptBlock(blk)
              else: ctx256.encryptBlock(blk)
    for k in 0 ..< 16: result[i + k] = enc[k]
    prev = enc
    i += 16

# --- CTS encryption (RFC 3962 §5) ---------------------------------

proc aesCtsEncrypt*(key, plaintext: openArray[byte]): seq[byte] =
  ## RFC 3962 §5 ciphertext-stealing mode (CS3 variant): zero-pad
  ## plaintext to a 16-byte multiple, do standard CBC with zero IV,
  ## swap the last two ciphertext blocks, then truncate the result back
  ## to the original plaintext length.
  doAssert plaintext.len >= 16, "AES-CTS needs ≥ 16 bytes of input"
  let zeroIv: array[16, byte] = [0'u8,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]
  if plaintext.len == 16:
    return aesCbcEncryptBlocks(key, zeroIv, plaintext)

  # Zero-pad to 16-byte multiple.
  let n = plaintext.len
  let padded = ((n + 15) div 16) * 16
  var ptPadded = newSeq[byte](padded)
  for i in 0 ..< n: ptPadded[i] = plaintext[i]
  let ct = aesCbcEncryptBlocks(key, zeroIv, ptPadded)
  # Swap last two 16-byte ciphertext blocks.
  var swapped = newSeq[byte](padded)
  for i in 0 ..< padded - 32: swapped[i] = ct[i]
  for i in 0 ..< 16: swapped[padded - 32 + i] = ct[padded - 16 + i]
  for i in 0 ..< 16: swapped[padded - 16 + i] = ct[padded - 32 + i]
  # Truncate to original plaintext length.
  result = swapped[0 ..< n]

# --- AES-CTS decryption (RFC 3962 §5) -----------------------------

proc aesCbcDecryptBlocks(key: openArray[byte]; iv: array[16, byte];
                         ciphertext: openArray[byte]): seq[byte] =
  doAssert ciphertext.len mod 16 == 0
  var ctx128: Aes128Ctx
  var ctx256: Aes256Ctx
  let is128 = key.len == 16
  if is128: ctx128.initAes128(key) else: ctx256.initAes256(key)
  result = newSeq[byte](ciphertext.len)
  var prev = iv
  var i = 0
  while i < ciphertext.len:
    var blk: array[16, byte]
    for k in 0 ..< 16: blk[k] = ciphertext[i + k]
    let dec = if is128: ctx128.decryptBlock(blk)
              else: ctx256.decryptBlock(blk)
    for k in 0 ..< 16: result[i + k] = dec[k] xor prev[k]
    for k in 0 ..< 16: prev[k] = ciphertext[i + k]
    i += 16

proc decryptSingleBlock(key: openArray[byte]; blk: array[16, byte]):
                       array[16, byte] =
  ## AES decrypt one block with no IV mixing.
  var ctx128: Aes128Ctx
  var ctx256: Aes256Ctx
  if key.len == 16:
    ctx128.initAes128(key)
    result = ctx128.decryptBlock(blk)
  else:
    ctx256.initAes256(key)
    result = ctx256.decryptBlock(blk)

proc aesCtsDecrypt*(key, ciphertext: openArray[byte]): seq[byte] =
  ## Inverse of aesCtsEncrypt (CS3). Reconstructs the missing high
  ## bytes of the truncated Cn-1 using the fact that the zero-padding
  ## in encryption forced AES⁻¹(Cn)[d..15] = Cn-1[d..15].
  doAssert ciphertext.len >= 16
  let zeroIv: array[16, byte] = [0'u8,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]
  if ciphertext.len == 16:
    return aesCbcDecryptBlocks(key, zeroIv, ciphertext)

  let n = ciphertext.len
  let lastLenRaw = n mod 16
  let lastLen = if lastLenRaw == 0: 16 else: lastLenRaw
  let padded = ((n + 15) div 16) * 16

  # Wire layout (after CS3 swap+truncate):
  #   wire[0 ..< padded-32]            = unchanged prior CBC blocks
  #   wire[padded-32 ..< padded-16]    = full Cn (the natural-last CBC out)
  #   wire[padded-16 ..< n]            = truncated Cn-1 (first lastLen bytes)
  # We need to recover Cn-1[lastLen..15] before un-swapping.
  var fullCt = newSeq[byte](padded)
  for i in 0 ..< n: fullCt[i] = ciphertext[i]
  if lastLen < 16:
    # Need the missing bytes of Cn-1. AES⁻¹(Cn)[lastLen..15] = Cn-1[lastLen..15].
    var cn: array[16, byte]
    for i in 0 ..< 16: cn[i] = ciphertext[padded - 32 + i]
    let cnDec = decryptSingleBlock(key, cn)
    for i in lastLen ..< 16:
      fullCt[padded - 16 + i] = cnDec[i]

  # Un-swap last two ciphertext blocks back to natural CBC order.
  var natural = newSeq[byte](padded)
  for i in 0 ..< padded - 32: natural[i] = fullCt[i]
  for i in 0 ..< 16: natural[padded - 32 + i] = fullCt[padded - 16 + i]
  for i in 0 ..< 16: natural[padded - 16 + i] = fullCt[padded - 32 + i]
  let plainPadded = aesCbcDecryptBlocks(key, zeroIv, natural)
  result = plainPadded[0 ..< n]

# --- DR / DK (RFC 3961 §5.3) --------------------------------------

proc derive*(baseKey, constant: openArray[byte]): seq[byte] =
  ## DR: produce key-length bytes by repeatedly AES-encrypting an
  ## n-folded constant in ECB until the buffer is at least keyLen.
  let keyLen = baseKey.len   # 16 for AES-128, 32 for AES-256
  var blk: array[16, byte]
  let folded =
    if constant.len == 16: @constant
    else: nfold(constant, 128)
  for i in 0 ..< 16: blk[i] = folded[i]
  var buf = newSeq[byte](0)
  var ctx128: Aes128Ctx
  var ctx256: Aes256Ctx
  let is128 = keyLen == 16
  if is128: ctx128.initAes128(baseKey) else: ctx256.initAes256(baseKey)
  while buf.len < keyLen:
    let enc = if is128: ctx128.encryptBlock(blk)
              else: ctx256.encryptBlock(blk)
    for x in enc: buf.add(x)
    blk = enc
  result = buf[0 ..< keyLen]

proc deriveKey*(baseKey, constant: openArray[byte]): seq[byte] =
  ## DK(K, C) = random-to-key(DR(K, C)). For AES, random-to-key is the
  ## identity (just take the bytes).
  result = derive(baseKey, constant)

proc usageConstant*(usage: uint32; selector: byte): array[5, byte] =
  ## Build the 5-byte constant `BE(usage) || selector` per RFC 3961 §5.3.
  ## Selector is 0xAA for Ke, 0x55 for Ki, 0x99 for Kc.
  result[0] = byte((usage shr 24) and 0xff)
  result[1] = byte((usage shr 16) and 0xff)
  result[2] = byte((usage shr 8) and 0xff)
  result[3] = byte(usage and 0xff)
  result[4] = selector

# --- string-to-key (RFC 3962 §4) ----------------------------------

const KerberosLabel = "kerberos"

proc stringToKey*(password, salt: openArray[byte]; etype: uint32;
                  iterations: int = 4096): seq[byte] =
  ## RFC 3962 §4. Full pipeline: PBKDF2 → tkey → base = DK(tkey, "kerberos").
  let dkLen = if etype == EtypeAes128: Aes128KeyLen
              elif etype == EtypeAes256: Aes256KeyLen
              else: 0
  doAssert dkLen > 0, "unsupported Kerberos etype: " & $etype
  let tkey = pbkdf2HmacSha1(password, salt, iterations, dkLen)
  var label = newSeq[byte](KerberosLabel.len)
  for i, c in KerberosLabel: label[i] = byte(c)
  result = deriveKey(tkey, label)

# --- HMAC truncated to 96 bits ------------------------------------

proc hmacSha1Truncated*(key, msg: openArray[byte]): array[12, byte] =
  ## HMAC-SHA1-96 (12 bytes), used by ETYPE 17 / 18 as the integrity tag.
  let full = hmacSha1(key, msg)
  for i in 0 ..< 12: result[i] = full[i]
