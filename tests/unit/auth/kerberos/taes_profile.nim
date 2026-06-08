## Round-trip the full AES-CTS-HMAC-SHA1-96 profile.

import std/[unittest, strutils]
import msrpc/auth/kerberos/[etype, aes]

proc str(s: string): seq[byte] =
  result = newSeq[byte](s.len)
  for i, c in s: result[i] = byte(c)

suite "Kerberos AES profile round-trip":
  test "AES-128: encrypt + decrypt recovers plaintext":
    let base = stringToKey(str("password"),
                           str("ATHENA.MIT.EDUraeburn"),
                           EtypeAes128, iterations = 1200)
    let pt = str("hello world!")
    let ct = aesEncrypt(base, pt, usage = 1'u32)
    let (rec, ok) = aesDecrypt(base, ct, usage = 1'u32)
    check ok
    check rec == pt

  test "AES-256: encrypt + decrypt recovers larger plaintext":
    let base = stringToKey(str("password"),
                           str("ATHENA.MIT.EDUraeburn"),
                           EtypeAes256, iterations = 1200)
    var pt = newSeq[byte](73)
    for i in 0 ..< 73: pt[i] = byte((i * 7 + 3) and 0xff)
    let ct = aesEncrypt(base, pt, usage = 3'u32)
    let (rec, ok) = aesDecrypt(base, ct, usage = 3'u32)
    check ok
    check rec == pt

  test "tampering with the HMAC fails verification":
    let base = stringToKey(str("password"), str("salt"),
                           EtypeAes128, iterations = 100)
    let pt = str("attack at dawn")
    var ct = aesEncrypt(base, pt, usage = 1'u32)
    ct[ct.len - 1] = ct[ct.len - 1] xor 0x01     # flip a bit in the MAC
    let (rec, ok) = aesDecrypt(base, ct, usage = 1'u32)
    check not ok
    check rec.len == 0

  test "tampering with the ciphertext fails verification":
    let base = stringToKey(str("password"), str("salt"),
                           EtypeAes128, iterations = 100)
    let pt = str("attack at dawn")
    var ct = aesEncrypt(base, pt, usage = 1'u32)
    ct[5] = ct[5] xor 0x80                       # flip a bit in the body
    let (rec, ok) = aesDecrypt(base, ct, usage = 1'u32)
    check not ok
