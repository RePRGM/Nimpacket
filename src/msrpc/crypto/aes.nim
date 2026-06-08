## aes.nim — AES-128 and AES-256 (FIPS 197). Pure Nim, no acceleration.
##
## Constant-time it is not; this implementation aims for correctness
## and portability rather than side-channel resistance. The crypto we
## ride on top (CMAC, CCM, GCM) typically uses AES only with random
## per-message inputs, so timing-leak surface is small.

type
  Aes128Ctx* = object
    roundKey*: array[176, byte]
  Aes256Ctx* = object
    roundKey*: array[240, byte]

# --- S-box and Rcon -------------------------------------------------

const Sbox: array[256, byte] = [
  0x63'u8, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
  0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
  0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
  0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
  0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
  0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
  0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
  0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
  0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
  0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
  0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
  0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
  0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
  0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
  0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
  0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16]

const Rcon: array[11, byte] = [
  0x00'u8, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]

template xtime(x: byte): byte =
  byte((uint8(x) shl 1) xor ((if (x and 0x80'u8) != 0: 0x1b'u8 else: 0)))

# --- key expansion --------------------------------------------------

proc expand128(c: var Aes128Ctx; key: openArray[byte]) =
  doAssert key.len == 16, "AES-128 key must be 16 bytes"
  for i in 0 ..< 16: c.roundKey[i] = key[i]
  var i = 16
  var rconIdx = 1
  while i < 176:
    var t: array[4, byte]
    for k in 0 ..< 4: t[k] = c.roundKey[i - 4 + k]
    if (i mod 16) == 0:
      let tmp = t[0]
      t[0] = Sbox[t[1]] xor Rcon[rconIdx]; inc rconIdx
      t[1] = Sbox[t[2]]
      t[2] = Sbox[t[3]]
      t[3] = Sbox[tmp]
    for k in 0 ..< 4:
      c.roundKey[i] = c.roundKey[i - 16] xor t[k]
      inc i

proc expand256(c: var Aes256Ctx; key: openArray[byte]) =
  doAssert key.len == 32, "AES-256 key must be 32 bytes"
  for i in 0 ..< 32: c.roundKey[i] = key[i]
  var i = 32
  var rconIdx = 1
  while i < 240:
    var t: array[4, byte]
    for k in 0 ..< 4: t[k] = c.roundKey[i - 4 + k]
    if (i mod 32) == 0:
      let tmp = t[0]
      t[0] = Sbox[t[1]] xor Rcon[rconIdx]; inc rconIdx
      t[1] = Sbox[t[2]]
      t[2] = Sbox[t[3]]
      t[3] = Sbox[tmp]
    elif (i mod 32) == 16:
      for k in 0 ..< 4: t[k] = Sbox[t[k]]
    for k in 0 ..< 4:
      c.roundKey[i] = c.roundKey[i - 32] xor t[k]
      inc i

proc initAes128*(c: var Aes128Ctx; key: openArray[byte]) =
  expand128(c, key)

proc initAes256*(c: var Aes256Ctx; key: openArray[byte]) =
  expand256(c, key)

# --- round operations ----------------------------------------------

proc subBytes(state: var array[16, byte]) =
  for i in 0 ..< 16: state[i] = Sbox[state[i]]

proc shiftRows(state: var array[16, byte]) =
  # row 0: no shift
  # row 1: left rotate by 1
  let t1 = state[1]; state[1] = state[5]; state[5] = state[9]; state[9] = state[13]; state[13] = t1
  # row 2: left rotate by 2
  let t2a = state[2]; let t2b = state[6]; state[2] = state[10]; state[6] = state[14]; state[10] = t2a; state[14] = t2b
  # row 3: left rotate by 3
  let t3 = state[15]; state[15] = state[11]; state[11] = state[7]; state[7] = state[3]; state[3] = t3

proc mixColumns(state: var array[16, byte]) =
  for col in 0 ..< 4:
    let i = col * 4
    let a0 = state[i]
    let a1 = state[i+1]
    let a2 = state[i+2]
    let a3 = state[i+3]
    let t = a0 xor a1 xor a2 xor a3
    state[i]   = a0 xor t xor xtime(a0 xor a1)
    state[i+1] = a1 xor t xor xtime(a1 xor a2)
    state[i+2] = a2 xor t xor xtime(a2 xor a3)
    state[i+3] = a3 xor t xor xtime(a3 xor a0)

proc addRoundKey(state: var array[16, byte]; roundKey: openArray[byte]; offset: int) =
  for i in 0 ..< 16: state[i] = state[i] xor roundKey[offset + i]

# --- single-block encryption ---------------------------------------

proc encryptBlock*(c: Aes128Ctx; input: array[16, byte]): array[16, byte] =
  var state = input
  addRoundKey(state, c.roundKey, 0)
  for round in 1 ..< 10:
    subBytes(state)
    shiftRows(state)
    mixColumns(state)
    addRoundKey(state, c.roundKey, round * 16)
  subBytes(state)
  shiftRows(state)
  addRoundKey(state, c.roundKey, 10 * 16)
  result = state

proc encryptBlock*(c: Aes256Ctx; input: array[16, byte]): array[16, byte] =
  var state = input
  addRoundKey(state, c.roundKey, 0)
  for round in 1 ..< 14:
    subBytes(state)
    shiftRows(state)
    mixColumns(state)
    addRoundKey(state, c.roundKey, round * 16)
  subBytes(state)
  shiftRows(state)
  addRoundKey(state, c.roundKey, 14 * 16)
  result = state

proc aes128Encrypt*(key, plaintext: openArray[byte]): array[16, byte] =
  doAssert plaintext.len == 16
  var c: Aes128Ctx
  c.initAes128(key)
  var blk: array[16, byte]
  for i in 0 ..< 16: blk[i] = plaintext[i]
  result = c.encryptBlock(blk)

proc aes256Encrypt*(key, plaintext: openArray[byte]): array[16, byte] =
  doAssert plaintext.len == 16
  var c: Aes256Ctx
  c.initAes256(key)
  var blk: array[16, byte]
  for i in 0 ..< 16: blk[i] = plaintext[i]
  result = c.encryptBlock(blk)
