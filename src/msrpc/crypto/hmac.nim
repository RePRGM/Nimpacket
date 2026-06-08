## hmac.nim — RFC 2104 HMAC, parameterized over the hash function.
##
## MS-NLMP uses HMAC-MD5 throughout NTLMv2.

import md5

const Md5BlockSize = 64
const Md5DigestSize = 16

proc hmacMd5*(key, message: openArray[byte]): array[16, byte] =
  ## RFC 2104. Tested against RFC 2202 test vectors.
  var k0: array[Md5BlockSize, byte]
  if key.len > Md5BlockSize:
    let kh = md5(key)
    for i in 0 ..< Md5DigestSize: k0[i] = kh[i]
  else:
    for i in 0 ..< key.len: k0[i] = key[i]

  var ipad: array[Md5BlockSize, byte]
  var opad: array[Md5BlockSize, byte]
  for i in 0 ..< Md5BlockSize:
    ipad[i] = k0[i] xor 0x36'u8
    opad[i] = k0[i] xor 0x5c'u8

  var inner = newSeq[byte](Md5BlockSize + message.len)
  for i in 0 ..< Md5BlockSize: inner[i] = ipad[i]
  for i in 0 ..< message.len: inner[Md5BlockSize + i] = message[i]
  let innerHash = md5(inner)

  var outer = newSeq[byte](Md5BlockSize + Md5DigestSize)
  for i in 0 ..< Md5BlockSize: outer[i] = opad[i]
  for i in 0 ..< Md5DigestSize: outer[Md5BlockSize + i] = innerHash[i]
  result = md5(outer)
