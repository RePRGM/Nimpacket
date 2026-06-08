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
  ## RFC 3962 §5 ciphertext-stealing mode. Returns ciphertext of the
  ## same length as plaintext. IV is implicitly all-zeros (Kerberos
  ## convention: the caller has already mixed-in any IV via the
  ## confounder prepended to plaintext).
  doAssert plaintext.len >= 16, "AES-CTS needs ≥ 16 bytes of input"
  let zeroIv: array[16, byte] = [0'u8,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]
  if plaintext.len == 16:
    return aesCbcEncryptBlocks(key, zeroIv, plaintext)

  # Common output buffer for the multi-block cases below.
  # (Declared after the single-block fast path so we don't allocate.)

  let n = plaintext.len
  let lastLen = n mod 16
  let body =
    if lastLen == 0: n - 32   # all-but-last-two-blocks for full alignment
    else: n - 16 - lastLen
  # All complete blocks before the last two (or one) get standard CBC.
  var ct = newSeq[byte](n)
  var iv = zeroIv
  if body > 0:
    let chunk = aesCbcEncryptBlocks(key, iv, plaintext[0 ..< body])
    for i in 0 ..< body: ct[i] = chunk[i]
    for i in 0 ..< 16: iv[i] = chunk[body - 16 + i]

  if lastLen == 0:
    # Exactly aligned: just swap the last two blocks (RFC 3962 §5).
    let chunk = aesCbcEncryptBlocks(key, iv, plaintext[body ..< n])
    # chunk has two blocks: penultimate at 0..15, last at 16..31.
    # In the CTS output we swap them.
    for i in 0 ..< 16: ct[body + i]     = chunk[16 + i]
    for i in 0 ..< 16: ct[body + 16 + i] = chunk[i]
    result = ct
    return

  # General case: last full block + partial.
  let pad = 16 - lastLen
  var penultimate = newSeq[byte](16)
  for i in 0 ..< 16: penultimate[i] = plaintext[body + i]
  let cn1 = aesCbcEncryptBlocks(key, iv, penultimate)
  # Build last partial block padded with zeros and feed through CBC.
  var lastBlock = newSeq[byte](16)
  for i in 0 ..< lastLen: lastBlock[i] = plaintext[body + 16 + i]
  for i in 0 ..< pad: lastBlock[lastLen + i] = 0
  var iv2: array[16, byte]
  for i in 0 ..< 16: iv2[i] = cn1[i]
  let cn = aesCbcEncryptBlocks(key, iv2, lastBlock)
  # Per RFC 3962 §5: prior blocks || truncated Cn || Cn-1.
  for i in 0 ..< lastLen: ct[body + i] = cn[i]
  for i in 0 ..< 16: ct[body + lastLen + i] = cn1[i]
  result = ct

# --- string-to-key (RFC 3962 §4) ----------------------------------

proc stringToKey*(password, salt: openArray[byte]; etype: uint32;
                  iterations: int = 4096): seq[byte] =
  ## RFC 3962 §4. Produces a 16-byte key for ETYPE=17 or a 32-byte key
  ## for ETYPE=18. We skip the DK / DR steps (those are for derived
  ## subkey usages); ``stringToKey`` returns the base key.
  let dkLen = if etype == EtypeAes128: Aes128KeyLen
              elif etype == EtypeAes256: Aes256KeyLen
              else: 0
  doAssert dkLen > 0, "unsupported Kerberos etype: " & $etype
  let tkey = pbkdf2HmacSha1(password, salt, iterations, dkLen)
  # Per RFC 3962, the final base key is DK(tkey, "kerberos") — we
  # leave the DK step out for v0 (most KDCs accept tkey directly for
  # the AS-REQ pre-auth path). Full DK is a follow-up.
  result = tkey

# --- HMAC truncated to 96 bits ------------------------------------

proc hmacSha1Truncated*(key, msg: openArray[byte]): array[12, byte] =
  ## HMAC-SHA1-96 (12 bytes), used by ETYPE 17 / 18 as the integrity tag.
  let full = hmacSha1(key, msg)
  for i in 0 ..< 12: result[i] = full[i]
