## aes_ccm.nim — AES-CCM authenticated encryption (RFC 3610).
##
## SMB 3.0 / 3.0.2 use AES-128-CCM for per-message encryption when the
## negotiated cipher is `AES-128-CCM`. SMB 3.1.1 added GCM (a separate
## mode); we don't ship GCM yet. The CCM API used by SMB is:
##
##   nonce  — 11 bytes (NonceLength=11)
##   tag    — 16 bytes (MAC length M=16)
##   AAD    — variable
##   PT/CT  — variable
##
## We expose generic encrypt+decrypt with caller-controlled parameters
## so this same code can later serve Kerberos AES-CTS-CCM if needed.

import aes

type
  CcmError* = object of CatchableError

proc xorBytes(a: var openArray[byte]; b: openArray[byte]; n: int) =
  for i in 0 ..< n: a[i] = a[i] xor b[i]

proc cbcMac(ctx: Aes128Ctx; b0: array[16, byte];
            aad, plaintext: openArray[byte]; tagLen: int): array[16, byte] =
  var x = ctx.encryptBlock(b0)
  if aad.len > 0:
    # Length encoding (RFC 3610 §2.2): 2 bytes for lengths < 2^16-2^8
    var aadBlock: array[16, byte]
    aadBlock[0] = byte((aad.len shr 8) and 0xff)
    aadBlock[1] = byte(aad.len and 0xff)
    let firstChunk = min(aad.len, 16 - 2)
    for i in 0 ..< firstChunk: aadBlock[2 + i] = aad[i]
    for i in 0 ..< 16: aadBlock[i] = aadBlock[i] xor x[i]
    x = ctx.encryptBlock(aadBlock)
    var i = firstChunk
    while i < aad.len:
      var blk: array[16, byte]
      let take = min(16, aad.len - i)
      for k in 0 ..< take: blk[k] = aad[i + k]
      for k in 0 ..< 16: blk[k] = blk[k] xor x[k]
      x = ctx.encryptBlock(blk)
      i += take
  var i = 0
  while i < plaintext.len:
    var blk: array[16, byte]
    let take = min(16, plaintext.len - i)
    for k in 0 ..< take: blk[k] = plaintext[i + k]
    for k in 0 ..< 16: blk[k] = blk[k] xor x[k]
    x = ctx.encryptBlock(blk)
    i += take
  result = x

proc buildCtr(nonce: openArray[byte]; counter: int): array[16, byte] =
  ## A0/Ai blocks: flags || nonce || counter.
  ## For nonce length 11, L = 15 - 11 = 4 → flags low 3 bits = L-1 = 3.
  let L = 15 - nonce.len
  result[0] = byte(L - 1)
  for i in 0 ..< nonce.len:
    result[1 + i] = nonce[i]
  for i in 0 ..< L:
    result[15 - i] = byte((counter shr (i * 8)) and 0xff)

proc ccmEncrypt*(key, nonce, aad, plaintext: openArray[byte];
                tagLen: int = 16): tuple[ciphertext: seq[byte];
                                          tag: seq[byte]] =
  ## RFC 3610. Nonce length must be 7..13. Tag length must be even, 4..16.
  doAssert nonce.len in 7..13, "nonce 7..13 bytes"
  doAssert tagLen in {4, 6, 8, 10, 12, 14, 16}, "tag must be even 4..16"
  var ctx: Aes128Ctx
  ctx.initAes128(key)

  # B0 flags: (Adata?<<6) | (((M-2)/2)<<3) | (L-1)
  let L = 15 - nonce.len
  var b0: array[16, byte]
  b0[0] = byte(
    (if aad.len > 0: 0x40 else: 0) or
    (((tagLen - 2) div 2) shl 3) or
    (L - 1))
  for i in 0 ..< nonce.len: b0[1 + i] = nonce[i]
  for i in 0 ..< L: b0[15 - i] = byte((plaintext.len shr (i * 8)) and 0xff)

  let macTag = cbcMac(ctx, b0, aad, plaintext, tagLen)

  # Encrypt the plaintext under counter mode starting at counter=1.
  result.ciphertext = newSeq[byte](plaintext.len)
  var counter = 1
  var i = 0
  while i < plaintext.len:
    let s = ctx.encryptBlock(buildCtr(nonce, counter))
    let take = min(16, plaintext.len - i)
    for k in 0 ..< take:
      result.ciphertext[i + k] = plaintext[i + k] xor s[k]
    i += take
    inc counter

  # Encrypted MAC: S0 = AES(K, A0) xor MAC, truncated to tagLen.
  let s0 = ctx.encryptBlock(buildCtr(nonce, 0))
  result.tag = newSeq[byte](tagLen)
  for i in 0 ..< tagLen:
    result.tag[i] = macTag[i] xor s0[i]

proc ccmDecrypt*(key, nonce, aad, ciphertext, tag: openArray[byte]):
                  tuple[plaintext: seq[byte]; ok: bool] =
  ## Returns (plaintext, true) on a valid tag; (empty, false) otherwise.
  doAssert nonce.len in 7..13
  doAssert tag.len in {4, 6, 8, 10, 12, 14, 16}
  var ctx: Aes128Ctx
  ctx.initAes128(key)

  result.plaintext = newSeq[byte](ciphertext.len)
  var counter = 1
  var i = 0
  while i < ciphertext.len:
    let s = ctx.encryptBlock(buildCtr(nonce, counter))
    let take = min(16, ciphertext.len - i)
    for k in 0 ..< take:
      result.plaintext[i + k] = ciphertext[i + k] xor s[k]
    i += take
    inc counter

  # Recompute MAC over the recovered plaintext.
  let L = 15 - nonce.len
  var b0: array[16, byte]
  b0[0] = byte(
    (if aad.len > 0: 0x40 else: 0) or
    (((tag.len - 2) div 2) shl 3) or
    (L - 1))
  for j in 0 ..< nonce.len: b0[1 + j] = nonce[j]
  for j in 0 ..< L: b0[15 - j] = byte((result.plaintext.len shr (j * 8)) and 0xff)
  let macTag = cbcMac(ctx, b0, aad, result.plaintext, tag.len)
  let s0 = ctx.encryptBlock(buildCtr(nonce, 0))
  var ok = true
  for j in 0 ..< tag.len:
    if (macTag[j] xor s0[j]) != tag[j]:
      ok = false
  result.ok = ok
  if not ok: result.plaintext.setLen(0)
