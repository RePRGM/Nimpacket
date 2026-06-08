## SHA-1 vectors from RFC 3174 §7.3 / FIPS 180-4 examples.
## SHA-256 vectors from FIPS 180-4.
## HMAC-SHA1 vectors from RFC 2202; HMAC-SHA256 from RFC 4231.

import std/[unittest, strutils]
import msrpc/crypto/[sha1, sha256, hmac_sha]

proc hex(d: openArray[byte]): string =
  for b in d: result.add toHex(int(b), 2).toLowerAscii

proc unhex(s: string): seq[byte] =
  for i in countup(0, s.len - 1, 2):
    result.add byte(parseHexInt(s[i ..< i+2]))

suite "sha1 (FIPS 180-4)":
  test "empty":
    check hex(sha1(@[])) == "da39a3ee5e6b4b0d3255bfef95601890afd80709"
  test "\"abc\"":
    check hex(sha1(cast[seq[byte]](@"abc"))) ==
      "a9993e364706816aba3e25717850c26c9cd0d89d"
  test "long abcdbc... 448 bits":
    check hex(sha1(cast[seq[byte]](
      @"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"))) ==
      "84983e441c3bd26ebaae4aa1f95129e5e54670f1"
  test "million 'a'":
    var s = newSeq[byte](1_000_000)
    for i in 0 ..< 1_000_000: s[i] = byte('a'.ord)
    check hex(sha1(s)) == "34aa973cd4c4daa4f61eeb2bdbad27316534016f"

suite "sha256 (FIPS 180-4)":
  test "empty":
    check hex(sha256(@[])) ==
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
  test "\"abc\"":
    check hex(sha256(cast[seq[byte]](@"abc"))) ==
      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
  test "long abcdbc... 448 bits":
    check hex(sha256(cast[seq[byte]](
      @"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"))) ==
      "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
  test "million 'a'":
    var s = newSeq[byte](1_000_000)
    for i in 0 ..< 1_000_000: s[i] = byte('a'.ord)
    check hex(sha256(s)) ==
      "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"

suite "hmac-sha1 (RFC 2202)":
  test "case 1: key=20×0x0b, msg=\"Hi There\"":
    let k = unhex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
    check hex(hmacSha1(k, cast[seq[byte]](@"Hi There"))) ==
      "b617318655057264e28bc0b6fb378c8ef146be00"

  test "case 2: key=\"Jefe\", msg=\"what do ya want for nothing?\"":
    check hex(hmacSha1(cast[seq[byte]](@"Jefe"),
                       cast[seq[byte]](@"what do ya want for nothing?"))) ==
      "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79"

  test "case 6: 80-byte key, longer than block":
    var k = newSeq[byte](80)
    for i in 0 ..< 80: k[i] = 0xaa
    check hex(hmacSha1(k, cast[seq[byte]](
      @"Test Using Larger Than Block-Size Key - Hash Key First"))) ==
      "aa4ae5e15272d00e95705637ce8a3b55ed402112"

suite "hmac-sha256 (RFC 4231)":
  test "case 1: key=20×0x0b, msg=\"Hi There\"":
    let k = unhex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
    check hex(hmacSha256(k, cast[seq[byte]](@"Hi There"))) ==
      "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"

  test "case 2: key=\"Jefe\", msg=\"what do ya want for nothing?\"":
    check hex(hmacSha256(cast[seq[byte]](@"Jefe"),
                          cast[seq[byte]](@"what do ya want for nothing?"))) ==
      "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
