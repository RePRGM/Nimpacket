## hmac_sha.nim — HMAC over SHA-1 and SHA-256 (RFC 2104).
##
## Generic HMAC pattern parameterized by the hash and its block size.

import sha1, sha256

# --- HMAC-SHA1 (block 64, output 20) -------------------------------

const Sha1Block = 64
const Sha1Digest = 20

proc hmacSha1*(key, message: openArray[byte]): array[20, byte] =
  var k0: array[Sha1Block, byte]
  if key.len > Sha1Block:
    let kh = sha1(key)
    for i in 0 ..< Sha1Digest: k0[i] = kh[i]
  else:
    for i in 0 ..< key.len: k0[i] = key[i]
  var ipad: array[Sha1Block, byte]
  var opad: array[Sha1Block, byte]
  for i in 0 ..< Sha1Block:
    ipad[i] = k0[i] xor 0x36'u8
    opad[i] = k0[i] xor 0x5c'u8
  var inner = newSeq[byte](Sha1Block + message.len)
  for i in 0 ..< Sha1Block: inner[i] = ipad[i]
  for i in 0 ..< message.len: inner[Sha1Block + i] = message[i]
  let innerHash = sha1(inner)
  var outer = newSeq[byte](Sha1Block + Sha1Digest)
  for i in 0 ..< Sha1Block: outer[i] = opad[i]
  for i in 0 ..< Sha1Digest: outer[Sha1Block + i] = innerHash[i]
  result = sha1(outer)

# --- HMAC-SHA256 (block 64, output 32) -----------------------------

const Sha256Block = 64
const Sha256Digest = 32

proc hmacSha256*(key, message: openArray[byte]): array[32, byte] =
  var k0: array[Sha256Block, byte]
  if key.len > Sha256Block:
    let kh = sha256(key)
    for i in 0 ..< Sha256Digest: k0[i] = kh[i]
  else:
    for i in 0 ..< key.len: k0[i] = key[i]
  var ipad: array[Sha256Block, byte]
  var opad: array[Sha256Block, byte]
  for i in 0 ..< Sha256Block:
    ipad[i] = k0[i] xor 0x36'u8
    opad[i] = k0[i] xor 0x5c'u8
  var inner = newSeq[byte](Sha256Block + message.len)
  for i in 0 ..< Sha256Block: inner[i] = ipad[i]
  for i in 0 ..< message.len: inner[Sha256Block + i] = message[i]
  let innerHash = sha256(inner)
  var outer = newSeq[byte](Sha256Block + Sha256Digest)
  for i in 0 ..< Sha256Block: outer[i] = opad[i]
  for i in 0 ..< Sha256Digest: outer[Sha256Block + i] = innerHash[i]
  result = sha256(outer)
