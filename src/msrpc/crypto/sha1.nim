## sha1.nim — FIPS 180-4 SHA-1. Pure Nim.
##
## Needed for Kerberos AES-CTS-HMAC-SHA1-96 (the AES128/256 ETYPEs
## that every modern KDC speaks). SHA-1 is broken for collision
## resistance; here it is a pinned protocol primitive.

type
  Sha1Ctx* = object
    state*: array[5, uint32]
    buf*: array[64, byte]
    bufLen*: int
    bitLen*: uint64

template rol(x: uint32; n: int): uint32 =
  ((x shl n) or (x shr (32 - n)))

proc initSha1*(c: var Sha1Ctx) =
  c.state[0] = 0x67452301'u32
  c.state[1] = 0xefcdab89'u32
  c.state[2] = 0x98badcfe'u32
  c.state[3] = 0x10325476'u32
  c.state[4] = 0xc3d2e1f0'u32
  c.bufLen = 0
  c.bitLen = 0

proc transform(c: var Sha1Ctx; block_data: array[64, byte]) =
  var w: array[80, uint32]
  for i in 0 ..< 16:
    w[i] =
      (uint32(block_data[i*4]) shl 24) or
      (uint32(block_data[i*4+1]) shl 16) or
      (uint32(block_data[i*4+2]) shl 8) or
      uint32(block_data[i*4+3])
  for i in 16 ..< 80:
    w[i] = rol(w[i-3] xor w[i-8] xor w[i-14] xor w[i-16], 1)

  var a = c.state[0]
  var b = c.state[1]
  var cc = c.state[2]
  var d = c.state[3]
  var e = c.state[4]

  for i in 0 ..< 80:
    var f, k: uint32
    if i < 20:
      f = (b and cc) or ((not b) and d); k = 0x5A827999'u32
    elif i < 40:
      f = b xor cc xor d; k = 0x6ED9EBA1'u32
    elif i < 60:
      f = (b and cc) or (b and d) or (cc and d); k = 0x8F1BBCDC'u32
    else:
      f = b xor cc xor d; k = 0xCA62C1D6'u32
    let temp = rol(a, 5) + f + e + k + w[i]
    e = d
    d = cc
    cc = rol(b, 30)
    b = a
    a = temp

  c.state[0] += a
  c.state[1] += b
  c.state[2] += cc
  c.state[3] += d
  c.state[4] += e

proc update*(c: var Sha1Ctx; data: openArray[byte]) =
  c.bitLen += uint64(data.len) * 8'u64
  var i = 0
  while i < data.len:
    let take = min(64 - c.bufLen, data.len - i)
    for k in 0 ..< take:
      c.buf[c.bufLen + k] = data[i + k]
    c.bufLen += take
    i += take
    if c.bufLen == 64:
      c.transform(c.buf)
      c.bufLen = 0

proc finalize*(c: var Sha1Ctx): array[20, byte] =
  c.buf[c.bufLen] = 0x80'u8
  c.bufLen += 1
  if c.bufLen > 56:
    for k in c.bufLen ..< 64: c.buf[k] = 0
    c.transform(c.buf)
    c.bufLen = 0
  for k in c.bufLen ..< 56: c.buf[k] = 0
  let bl = c.bitLen
  # SHA-1 length is big-endian
  for i in 0 ..< 8:
    c.buf[56 + i] = byte((bl shr ((7 - i) * 8)) and 0xff'u64)
  c.transform(c.buf)
  for i in 0 ..< 5:
    let s = c.state[i]
    result[i*4]     = byte((s shr 24) and 0xff'u32)
    result[i*4 + 1] = byte((s shr 16) and 0xff'u32)
    result[i*4 + 2] = byte((s shr 8) and 0xff'u32)
    result[i*4 + 3] = byte(s and 0xff'u32)

proc sha1*(data: openArray[byte]): array[20, byte] =
  var c: Sha1Ctx
  initSha1(c)
  update(c, data)
  result = finalize(c)
