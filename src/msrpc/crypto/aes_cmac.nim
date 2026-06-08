## aes_cmac.nim — AES-CMAC (RFC 4493).
##
## CMAC is what SMB 3.0 / 3.0.2 uses for per-message signing.
## Replaces the HMAC-MD5/SHA-256 path for older SMB versions.

import aes

const BlockSize = 16

proc shiftLeft(input: openArray[byte]; output: var openArray[byte]) =
  var overflow: byte = 0
  for i in countdown(input.len - 1, 0):
    output[i] = byte((uint8(input[i]) shl 1) or overflow)
    overflow = (input[i] shr 7) and 1'u8

proc generateSubkeys128(c: Aes128Ctx): (array[16, byte], array[16, byte]) =
  ## Per RFC 4493 §2.3: derive K1 and K2 from L = AES(K, 0^128).
  const Rb: byte = 0x87
  let zero: array[16, byte] = [0'u8, 0, 0, 0, 0, 0, 0, 0,
                                0, 0, 0, 0, 0, 0, 0, 0]
  let L = c.encryptBlock(zero)
  var k1: array[16, byte]
  shiftLeft(L, k1)
  if (L[0] and 0x80'u8) != 0:
    k1[15] = k1[15] xor Rb
  var k2: array[16, byte]
  shiftLeft(k1, k2)
  if (k1[0] and 0x80'u8) != 0:
    k2[15] = k2[15] xor Rb
  result = (k1, k2)

proc aesCmac128*(key, message: openArray[byte]): array[16, byte] =
  ## RFC 4493 AES-CMAC with a 128-bit key.
  var ctx: Aes128Ctx
  ctx.initAes128(key)
  let (k1, k2) = generateSubkeys128(ctx)

  let n = if message.len == 0: 1
          else: (message.len + BlockSize - 1) div BlockSize
  let lastIsComplete = message.len > 0 and (message.len mod BlockSize) == 0

  var lastBlock: array[16, byte]
  let lastStart = (n - 1) * BlockSize
  if lastIsComplete:
    for i in 0 ..< BlockSize:
      lastBlock[i] = message[lastStart + i] xor k1[i]
  else:
    let leftover = message.len - lastStart
    for i in 0 ..< leftover: lastBlock[i] = message[lastStart + i]
    lastBlock[leftover] = 0x80
    # rest already zero
    for i in 0 ..< BlockSize: lastBlock[i] = lastBlock[i] xor k2[i]

  var x: array[16, byte]
  for block_idx in 0 ..< n - 1:
    var y: array[16, byte]
    for i in 0 ..< 16:
      y[i] = x[i] xor message[block_idx * BlockSize + i]
    x = ctx.encryptBlock(y)
  var y: array[16, byte]
  for i in 0 ..< 16: y[i] = x[i] xor lastBlock[i]
  result = ctx.encryptBlock(y)
