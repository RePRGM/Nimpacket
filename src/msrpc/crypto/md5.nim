## md5.nim — RFC 1321 MD5. Pure-Nim, no external deps.
##
## Like MD4 here, MD5 is a pinned protocol primitive (HMAC-MD5 inside
## NTLMv2), not a recommendation for new code.

type
  Md5Ctx* = object
    state*: array[4, uint32]
    buf*: array[64, byte]
    bufLen*: int
    bitLen*: uint64

template rol(x: uint32; n: int): uint32 =
  ((x shl n) or (x shr (32 - n)))

const T: array[64, uint32] = [
  0xd76aa478'u32, 0xe8c7b756'u32, 0x242070db'u32, 0xc1bdceee'u32,
  0xf57c0faf'u32, 0x4787c62a'u32, 0xa8304613'u32, 0xfd469501'u32,
  0x698098d8'u32, 0x8b44f7af'u32, 0xffff5bb1'u32, 0x895cd7be'u32,
  0x6b901122'u32, 0xfd987193'u32, 0xa679438e'u32, 0x49b40821'u32,

  0xf61e2562'u32, 0xc040b340'u32, 0x265e5a51'u32, 0xe9b6c7aa'u32,
  0xd62f105d'u32, 0x02441453'u32, 0xd8a1e681'u32, 0xe7d3fbc8'u32,
  0x21e1cde6'u32, 0xc33707d6'u32, 0xf4d50d87'u32, 0x455a14ed'u32,
  0xa9e3e905'u32, 0xfcefa3f8'u32, 0x676f02d9'u32, 0x8d2a4c8a'u32,

  0xfffa3942'u32, 0x8771f681'u32, 0x6d9d6122'u32, 0xfde5380c'u32,
  0xa4beea44'u32, 0x4bdecfa9'u32, 0xf6bb4b60'u32, 0xbebfbc70'u32,
  0x289b7ec6'u32, 0xeaa127fa'u32, 0xd4ef3085'u32, 0x04881d05'u32,
  0xd9d4d039'u32, 0xe6db99e5'u32, 0x1fa27cf8'u32, 0xc4ac5665'u32,

  0xf4292244'u32, 0x432aff97'u32, 0xab9423a7'u32, 0xfc93a039'u32,
  0x655b59c3'u32, 0x8f0ccc92'u32, 0xffeff47d'u32, 0x85845dd1'u32,
  0x6fa87e4f'u32, 0xfe2ce6e0'u32, 0xa3014314'u32, 0x4e0811a1'u32,
  0xf7537e82'u32, 0xbd3af235'u32, 0x2ad7d2bb'u32, 0xeb86d391'u32]

const S: array[64, int] = [
  7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
  5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20,
  4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
  6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21]

proc initMd5*(c: var Md5Ctx) =
  c.state[0] = 0x67452301'u32
  c.state[1] = 0xefcdab89'u32
  c.state[2] = 0x98badcfe'u32
  c.state[3] = 0x10325476'u32
  c.bufLen = 0
  c.bitLen = 0

proc transform(c: var Md5Ctx; block_data: array[64, byte]) =
  var x: array[16, uint32]
  for i in 0 ..< 16:
    x[i] =
      uint32(block_data[i*4]) or
      (uint32(block_data[i*4+1]) shl 8) or
      (uint32(block_data[i*4+2]) shl 16) or
      (uint32(block_data[i*4+3]) shl 24)

  var a = c.state[0]
  var b = c.state[1]
  var cc = c.state[2]
  var d = c.state[3]

  for i in 0 ..< 64:
    var f: uint32
    var g: int
    if i < 16:
      f = (b and cc) or ((not b) and d); g = i
    elif i < 32:
      f = (d and b) or ((not d) and cc); g = (5*i + 1) mod 16
    elif i < 48:
      f = b xor cc xor d; g = (3*i + 5) mod 16
    else:
      f = cc xor (b or (not d)); g = (7*i) mod 16
    let tmp = d
    d = cc
    cc = b
    b = b + rol(a + f + T[i] + x[g], S[i])
    a = tmp

  c.state[0] += a
  c.state[1] += b
  c.state[2] += cc
  c.state[3] += d

proc update*(c: var Md5Ctx; data: openArray[byte]) =
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

proc finalize*(c: var Md5Ctx): array[16, byte] =
  c.buf[c.bufLen] = 0x80'u8
  c.bufLen += 1
  if c.bufLen > 56:
    for k in c.bufLen ..< 64: c.buf[k] = 0
    c.transform(c.buf)
    c.bufLen = 0
  for k in c.bufLen ..< 56: c.buf[k] = 0
  let bl = c.bitLen
  for i in 0 ..< 8:
    c.buf[56 + i] = byte((bl shr (i * 8)) and 0xff'u64)
  c.transform(c.buf)
  for i in 0 ..< 4:
    let s = c.state[i]
    result[i*4]     = byte(s and 0xff'u32)
    result[i*4 + 1] = byte((s shr 8) and 0xff'u32)
    result[i*4 + 2] = byte((s shr 16) and 0xff'u32)
    result[i*4 + 3] = byte((s shr 24) and 0xff'u32)

proc md5*(data: openArray[byte]): array[16, byte] =
  var c: Md5Ctx
  initMd5(c)
  update(c, data)
  result = finalize(c)
