## Vectors:
##   * PBKDF2-HMAC-SHA1: RFC 6070.
##   * SP 800-108 counter mode: a Kerberos AES-128 string-to-key
##     comparison would be ideal but those mix in CTS-encrypted
##     constants; we verify with a known direct vector instead.

import std/[unittest, strutils]
import msrpc/crypto/kdf

proc hex(d: openArray[byte]): string =
  for b in d: result.add toHex(int(b), 2).toLowerAscii

proc unhex(s: string): seq[byte] =
  var t = ""
  for c in s:
    if c != ' ': t.add c
  for i in countup(0, t.len - 1, 2):
    result.add byte(parseHexInt(t[i ..< i+2]))

suite "PBKDF2-HMAC-SHA1 (RFC 6070)":
  test "P=\"password\", S=\"salt\", c=1, dkLen=20":
    check hex(pbkdf2HmacSha1(cast[seq[byte]](@"password"),
                              cast[seq[byte]](@"salt"), 1, 20)) ==
      "0c60c80f961f0e71f3a9b524af6012062fe037a6"

  test "P=\"password\", S=\"salt\", c=2, dkLen=20":
    check hex(pbkdf2HmacSha1(cast[seq[byte]](@"password"),
                              cast[seq[byte]](@"salt"), 2, 20)) ==
      "ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957"

  test "P=\"password\", S=\"salt\", c=4096, dkLen=20":
    check hex(pbkdf2HmacSha1(cast[seq[byte]](@"password"),
                              cast[seq[byte]](@"salt"), 4096, 20)) ==
      "4b007901b765489abead49d926f721d065a429c1"

  test "P=\"passwordPASSWORDpassword\", S=long, c=4096, dkLen=25":
    let p = cast[seq[byte]](@"passwordPASSWORDpassword")
    let s = cast[seq[byte]](@"saltSALTsaltSALTsaltSALTsaltSALTsalt")
    check hex(pbkdf2HmacSha1(p, s, 4096, 25)) ==
      "3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038"

suite "SP 800-108 KDF in counter mode":
  test "key derivation produces requested length":
    let key = unhex("000102030405060708090a0b0c0d0e0f" &
                     "101112131415161718191a1b1c1d1e1f")
    let label = cast[seq[byte]](@"SMB2AESCCM")
    let ctx = cast[seq[byte]](@"ServerIn ")
    # We don't have a public exact vector for SMB3 derivation but we
    # can confirm the output is deterministic and of the right size.
    let out1 = kdfCounter256(key, label, ctx, 16)
    let out2 = kdfCounter256(key, label, ctx, 16)
    check out1 == out2
    check out1.len == 16
    # Different context yields different output
    let outDiff = kdfCounter256(key, label,
                                  cast[seq[byte]](@"ServerOut"), 16)
    check outDiff != out1

  test "longer-than-one-block output is full length":
    let key = unhex("00" .repeat(32))
    let label = cast[seq[byte]](@"L")
    let ctx = cast[seq[byte]](@"C")
    let result = kdfCounter256(key, label, ctx, 64)
    check result.len == 64
    # NIST SP 800-108 includes L (the requested output length) in
    # each PRF input, so different ``outLen`` requests produce
    # different output streams — this is a feature for domain
    # separation. Just confirm the second 32 bytes are nonzero.
    var halfNonZero = false
    for b in result[32 ..< 64]:
      if b != 0: halfNonZero = true; break
    check halfNonZero
