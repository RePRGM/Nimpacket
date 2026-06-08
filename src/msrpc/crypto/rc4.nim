## rc4.nim — RC4 stream cipher.
##
## Used by NTLM for SEAL when AES is not negotiated. RC4 is broken for
## general purposes; the protocol pins it.

type
  Rc4Ctx* = object
    s*: array[256, byte]
    i*, j*: int

proc initRc4*(c: var Rc4Ctx; key: openArray[byte]) =
  ## KSA — Key Scheduling Algorithm.
  doAssert key.len > 0, "rc4 key cannot be empty"
  for k in 0 ..< 256: c.s[k] = byte(k)
  var j = 0
  for i in 0 ..< 256:
    j = (j + int(c.s[i]) + int(key[i mod key.len])) and 0xFF
    swap(c.s[i], c.s[j])
  c.i = 0
  c.j = 0

proc apply*(c: var Rc4Ctx; data: openArray[byte]): seq[byte] =
  ## PRGA — Pseudo-Random Generation Algorithm. RC4 is a stream cipher
  ## so encrypt and decrypt are the same operation.
  result = newSeq[byte](data.len)
  var i = c.i
  var j = c.j
  for k in 0 ..< data.len:
    i = (i + 1) and 0xFF
    j = (j + int(c.s[i])) and 0xFF
    swap(c.s[i], c.s[j])
    let t = (int(c.s[i]) + int(c.s[j])) and 0xFF
    result[k] = data[k] xor c.s[t]
  c.i = i
  c.j = j

proc apply*(c: var Rc4Ctx; data: var openArray[byte]) =
  ## In-place variant.
  var i = c.i
  var j = c.j
  for k in 0 ..< data.len:
    i = (i + 1) and 0xFF
    j = (j + int(c.s[i])) and 0xFF
    swap(c.s[i], c.s[j])
    let t = (int(c.s[i]) + int(c.s[j])) and 0xFF
    data[k] = data[k] xor c.s[t]
  c.i = i
  c.j = j

proc rc4*(key, data: openArray[byte]): seq[byte] =
  var c: Rc4Ctx
  c.initRc4(key)
  result = c.apply(data)
