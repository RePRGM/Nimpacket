## kdf.nim — key derivation functions.
##
## Two we need:
##   * PBKDF2-HMAC-SHA1 — Kerberos AES-CTS string-to-key (RFC 3962).
##   * NIST SP 800-108 counter-mode (KBKDF) — SMB3 session key
##     derivation. Underlying PRF is HMAC-SHA-256.

import hmac_sha

# --- PBKDF2-HMAC-SHA1 (RFC 2898) -----------------------------------

proc pbkdf2HmacSha1*(password, salt: openArray[byte];
                     iterations, dkLen: int): seq[byte] =
  doAssert dkLen > 0 and dkLen <= 0xFFFFFFFF
  doAssert iterations > 0

  let blocks = (dkLen + 19) div 20
  result = newSeq[byte](dkLen)
  var written = 0
  for i in 1 .. blocks:
    # T_i = U_1 xor U_2 xor ... xor U_iterations
    # U_1 = PRF(password, salt || INT_BE(i))
    # U_k = PRF(password, U_{k-1})
    var input = newSeq[byte](salt.len + 4)
    for k in 0 ..< salt.len: input[k] = salt[k]
    input[salt.len]     = byte((i shr 24) and 0xff)
    input[salt.len + 1] = byte((i shr 16) and 0xff)
    input[salt.len + 2] = byte((i shr 8) and 0xff)
    input[salt.len + 3] = byte(i and 0xff)
    var u = hmacSha1(password, input)
    var t = u
    for k in 2 .. iterations:
      u = hmacSha1(password, u)
      for j in 0 ..< 20: t[j] = t[j] xor u[j]
    let take = min(20, dkLen - written)
    for j in 0 ..< take:
      result[written + j] = t[j]
    written += take

# --- NIST SP 800-108 counter mode KBKDF (HMAC-SHA-256 PRF) ---------

proc kdfCounter256*(key, label, context: openArray[byte];
                    outLen: int): seq[byte] =
  ## L is encoded in *bits*, not bytes. Layout each iteration:
  ##   K(i) = PRF(K, [i]32 || Label || 0x00 || Context || [L]32)
  doAssert outLen > 0
  let outBits = outLen * 8
  let blocks = (outLen + 31) div 32
  result = newSeq[byte](outLen)
  var written = 0
  for i in 1 .. blocks:
    var msg = newSeq[byte](4 + label.len + 1 + context.len + 4)
    msg[0] = byte((i shr 24) and 0xff)
    msg[1] = byte((i shr 16) and 0xff)
    msg[2] = byte((i shr 8) and 0xff)
    msg[3] = byte(i and 0xff)
    var off = 4
    for b in label: msg[off] = b; inc off
    msg[off] = 0; inc off
    for b in context: msg[off] = b; inc off
    msg[off]     = byte((outBits shr 24) and 0xff)
    msg[off + 1] = byte((outBits shr 16) and 0xff)
    msg[off + 2] = byte((outBits shr 8) and 0xff)
    msg[off + 3] = byte(outBits and 0xff)
    let kI = hmacSha256(key, msg)
    let take = min(32, outLen - written)
    for j in 0 ..< take:
      result[written + j] = kI[j]
    written += take
