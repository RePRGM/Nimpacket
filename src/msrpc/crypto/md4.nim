## md4.nim — RFC 1320 MD4.
##
## MD4 is needed for NTLM NTOWFv1/NTOWFv2: ``MD4(UTF-16LE(password))``.
## It is broken for general use; here it is a fixed protocol primitive.

type
  Md4Ctx* = object
    state*: array[4, uint32]
    buf*: array[64, byte]
    bufLen*: int
    bitLen*: uint64

template rol(x: uint32; n: int): uint32 =
  ((x shl n) or (x shr (32 - n)))

proc initMd4*(c: var Md4Ctx) =
  c.state[0] = 0x67452301'u32
  c.state[1] = 0xefcdab89'u32
  c.state[2] = 0x98badcfe'u32
  c.state[3] = 0x10325476'u32
  c.bufLen = 0
  c.bitLen = 0

proc transform(c: var Md4Ctx; block_data: array[64, byte]) =
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

  template f(x, y, z: uint32): uint32 = ((x and y) or ((not x) and z))
  template g(x, y, z: uint32): uint32 = ((x and y) or (x and z) or (y and z))
  template h(x, y, z: uint32): uint32 = (x xor y xor z)

  template ff(a, b, cc, d, k, s) =
    a = rol(a + f(b, cc, d) + x[k], s)
  template gg(a, b, cc, d, k, s) =
    a = rol(a + g(b, cc, d) + x[k] + 0x5a827999'u32, s)
  template hh(a, b, cc, d, k, s) =
    a = rol(a + h(b, cc, d) + x[k] + 0x6ed9eba1'u32, s)

  ff(a, b, cc, d, 0, 3);  ff(d, a, b, cc, 1, 7);  ff(cc, d, a, b, 2, 11); ff(b, cc, d, a, 3, 19)
  ff(a, b, cc, d, 4, 3);  ff(d, a, b, cc, 5, 7);  ff(cc, d, a, b, 6, 11); ff(b, cc, d, a, 7, 19)
  ff(a, b, cc, d, 8, 3);  ff(d, a, b, cc, 9, 7);  ff(cc, d, a, b,10, 11); ff(b, cc, d, a,11, 19)
  ff(a, b, cc, d,12, 3);  ff(d, a, b, cc,13, 7);  ff(cc, d, a, b,14, 11); ff(b, cc, d, a,15, 19)

  gg(a, b, cc, d, 0, 3);  gg(d, a, b, cc, 4, 5);  gg(cc, d, a, b, 8,  9); gg(b, cc, d, a,12, 13)
  gg(a, b, cc, d, 1, 3);  gg(d, a, b, cc, 5, 5);  gg(cc, d, a, b, 9,  9); gg(b, cc, d, a,13, 13)
  gg(a, b, cc, d, 2, 3);  gg(d, a, b, cc, 6, 5);  gg(cc, d, a, b,10,  9); gg(b, cc, d, a,14, 13)
  gg(a, b, cc, d, 3, 3);  gg(d, a, b, cc, 7, 5);  gg(cc, d, a, b,11,  9); gg(b, cc, d, a,15, 13)

  hh(a, b, cc, d, 0, 3);  hh(d, a, b, cc, 8, 9);  hh(cc, d, a, b, 4, 11); hh(b, cc, d, a,12, 15)
  hh(a, b, cc, d, 2, 3);  hh(d, a, b, cc,10, 9);  hh(cc, d, a, b, 6, 11); hh(b, cc, d, a,14, 15)
  hh(a, b, cc, d, 1, 3);  hh(d, a, b, cc, 9, 9);  hh(cc, d, a, b, 5, 11); hh(b, cc, d, a,13, 15)
  hh(a, b, cc, d, 3, 3);  hh(d, a, b, cc,11, 9);  hh(cc, d, a, b, 7, 11); hh(b, cc, d, a,15, 15)

  c.state[0] += a
  c.state[1] += b
  c.state[2] += cc
  c.state[3] += d

proc update*(c: var Md4Ctx; data: openArray[byte]) =
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

proc finalize*(c: var Md4Ctx): array[16, byte] =
  # 0x80 then zeros then bit-length as little-endian u64
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

proc md4*(data: openArray[byte]): array[16, byte] =
  var c: Md4Ctx
  initMd4(c)
  update(c, data)
  result = finalize(c)
