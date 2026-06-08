## sha256.nim — FIPS 180-4 SHA-256. Pure Nim.
##
## Needed for SMB3 signing (HMAC-SHA-256 in dialect 3.0+) and
## modern Kerberos extensions.

type
  Sha256Ctx* = object
    state*: array[8, uint32]
    buf*: array[64, byte]
    bufLen*: int
    bitLen*: uint64

const K: array[64, uint32] = [
  0x428a2f98'u32, 0x71374491'u32, 0xb5c0fbcf'u32, 0xe9b5dba5'u32,
  0x3956c25b'u32, 0x59f111f1'u32, 0x923f82a4'u32, 0xab1c5ed5'u32,
  0xd807aa98'u32, 0x12835b01'u32, 0x243185be'u32, 0x550c7dc3'u32,
  0x72be5d74'u32, 0x80deb1fe'u32, 0x9bdc06a7'u32, 0xc19bf174'u32,
  0xe49b69c1'u32, 0xefbe4786'u32, 0x0fc19dc6'u32, 0x240ca1cc'u32,
  0x2de92c6f'u32, 0x4a7484aa'u32, 0x5cb0a9dc'u32, 0x76f988da'u32,
  0x983e5152'u32, 0xa831c66d'u32, 0xb00327c8'u32, 0xbf597fc7'u32,
  0xc6e00bf3'u32, 0xd5a79147'u32, 0x06ca6351'u32, 0x14292967'u32,
  0x27b70a85'u32, 0x2e1b2138'u32, 0x4d2c6dfc'u32, 0x53380d13'u32,
  0x650a7354'u32, 0x766a0abb'u32, 0x81c2c92e'u32, 0x92722c85'u32,
  0xa2bfe8a1'u32, 0xa81a664b'u32, 0xc24b8b70'u32, 0xc76c51a3'u32,
  0xd192e819'u32, 0xd6990624'u32, 0xf40e3585'u32, 0x106aa070'u32,
  0x19a4c116'u32, 0x1e376c08'u32, 0x2748774c'u32, 0x34b0bcb5'u32,
  0x391c0cb3'u32, 0x4ed8aa4a'u32, 0x5b9cca4f'u32, 0x682e6ff3'u32,
  0x748f82ee'u32, 0x78a5636f'u32, 0x84c87814'u32, 0x8cc70208'u32,
  0x90befffa'u32, 0xa4506ceb'u32, 0xbef9a3f7'u32, 0xc67178f2'u32]

template ror(x: uint32; n: int): uint32 =
  ((x shr n) or (x shl (32 - n)))

proc initSha256*(c: var Sha256Ctx) =
  c.state[0] = 0x6a09e667'u32
  c.state[1] = 0xbb67ae85'u32
  c.state[2] = 0x3c6ef372'u32
  c.state[3] = 0xa54ff53a'u32
  c.state[4] = 0x510e527f'u32
  c.state[5] = 0x9b05688c'u32
  c.state[6] = 0x1f83d9ab'u32
  c.state[7] = 0x5be0cd19'u32
  c.bufLen = 0
  c.bitLen = 0

proc transform(c: var Sha256Ctx; block_data: array[64, byte]) =
  var w: array[64, uint32]
  for i in 0 ..< 16:
    w[i] =
      (uint32(block_data[i*4]) shl 24) or
      (uint32(block_data[i*4+1]) shl 16) or
      (uint32(block_data[i*4+2]) shl 8) or
      uint32(block_data[i*4+3])
  for i in 16 ..< 64:
    let s0 = ror(w[i-15], 7) xor ror(w[i-15], 18) xor (w[i-15] shr 3)
    let s1 = ror(w[i-2], 17) xor ror(w[i-2], 19) xor (w[i-2] shr 10)
    w[i] = w[i-16] + s0 + w[i-7] + s1

  var a = c.state[0]
  var b = c.state[1]
  var cc = c.state[2]
  var d = c.state[3]
  var e = c.state[4]
  var f = c.state[5]
  var g = c.state[6]
  var h = c.state[7]

  for i in 0 ..< 64:
    let s1 = ror(e, 6) xor ror(e, 11) xor ror(e, 25)
    let ch = (e and f) xor ((not e) and g)
    let t1 = h + s1 + ch + K[i] + w[i]
    let s0 = ror(a, 2) xor ror(a, 13) xor ror(a, 22)
    let mj = (a and b) xor (a and cc) xor (b and cc)
    let t2 = s0 + mj
    h = g
    g = f
    f = e
    e = d + t1
    d = cc
    cc = b
    b = a
    a = t1 + t2

  c.state[0] += a; c.state[1] += b; c.state[2] += cc; c.state[3] += d
  c.state[4] += e; c.state[5] += f; c.state[6] += g; c.state[7] += h

proc update*(c: var Sha256Ctx; data: openArray[byte]) =
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

proc finalize*(c: var Sha256Ctx): array[32, byte] =
  c.buf[c.bufLen] = 0x80'u8
  c.bufLen += 1
  if c.bufLen > 56:
    for k in c.bufLen ..< 64: c.buf[k] = 0
    c.transform(c.buf)
    c.bufLen = 0
  for k in c.bufLen ..< 56: c.buf[k] = 0
  let bl = c.bitLen
  for i in 0 ..< 8:
    c.buf[56 + i] = byte((bl shr ((7 - i) * 8)) and 0xff'u64)
  c.transform(c.buf)
  for i in 0 ..< 8:
    let s = c.state[i]
    result[i*4]     = byte((s shr 24) and 0xff'u32)
    result[i*4 + 1] = byte((s shr 16) and 0xff'u32)
    result[i*4 + 2] = byte((s shr 8) and 0xff'u32)
    result[i*4 + 3] = byte(s and 0xff'u32)

proc sha256*(data: openArray[byte]): array[32, byte] =
  var c: Sha256Ctx
  initSha256(c)
  update(c, data)
  result = finalize(c)
