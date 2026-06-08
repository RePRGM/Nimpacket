## RC4-HMAC unit tests.
##
## RFC 4757 doesn't publish many vector tables but the NT-hash and
## key-derivation steps are testable on their own.

import std/[unittest, strutils]
import msrpc/auth/kerberos/rc4

proc hex(d: openArray[byte]): string =
  for b in d: result.add toHex(int(b), 2).toLowerAscii

suite "Kerberos RC4-HMAC string-to-key":
  test "NT hash of 'Password' matches MS-NLMP §4.2.2":
    # Same vector we use for NTLMv1: NT hash = a4f49c40 6510bdca b6824ee7 c30fd852
    check hex(rc4HmacStringToKey("Password")) ==
      "a4f49c406510bdcab6824ee7c30fd852"

  test "Different passwords yield different keys":
    check rc4HmacStringToKey("abc") != rc4HmacStringToKey("ABC")

suite "Kerberos RC4-HMAC encryption round-trip":
  test "encrypt then decrypt recovers the plaintext":
    let key = rc4HmacStringToKey("Password")
    let pt = cast[seq[byte]](@"Hello Kerberos RC4-HMAC")
    let ct = rc4HmacEncrypt(key, pt, usage = 1)
    check ct.len == pt.len + 24
    let (pt2, ok) = rc4HmacDecrypt(key, ct, usage = 1)
    check ok
    check pt2 == pt

  test "tampered ciphertext fails verification":
    let key = rc4HmacStringToKey("Password")
    let pt = cast[seq[byte]](@"top secret")
    var ct = rc4HmacEncrypt(key, pt, usage = 7)
    ct[20] = ct[20] xor 0x01
    let (pt2, ok) = rc4HmacDecrypt(key, ct, usage = 7)
    check (not ok)
    check pt2.len == 0

  test "wrong usage number fails":
    let key = rc4HmacStringToKey("Password")
    let pt = cast[seq[byte]](@"checking usage")
    let ct = rc4HmacEncrypt(key, pt, usage = 1)
    let (pt2, ok) = rc4HmacDecrypt(key, ct, usage = 2)
    check (not ok)

  test "ciphertext is different for each call (random confounder)":
    let key = rc4HmacStringToKey("Password")
    let pt = cast[seq[byte]](@"same plaintext")
    let ct1 = rc4HmacEncrypt(key, pt, usage = 1)
    let ct2 = rc4HmacEncrypt(key, pt, usage = 1)
    check ct1 != ct2
    # Both decrypt to the same plaintext though.
    let (p1, ok1) = rc4HmacDecrypt(key, ct1, usage = 1)
    let (p2, ok2) = rc4HmacDecrypt(key, ct2, usage = 1)
    check ok1 and ok2
    check p1 == pt and p2 == pt
