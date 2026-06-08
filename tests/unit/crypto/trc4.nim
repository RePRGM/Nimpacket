## RC4 test vectors. Sources:
##  - RFC 6229 §A.1: KEY=0102030405 with offsets 0, 16, 32
##  - Classic vector "Key" / "Plaintext"

import std/[unittest, strutils]
import msrpc/crypto/rc4

proc hex(d: openArray[byte]): string =
  for b in d: result.add toHex(int(b), 2).toLowerAscii

proc unhex(s: string): seq[byte] =
  for i in countup(0, s.len - 1, 2):
    result.add byte(parseHexInt(s[i ..< i+2]))

suite "rc4":
  test "classic: key=\"Key\", plaintext=\"Plaintext\"":
    let cipher = rc4(cast[seq[byte]](@"Key"), cast[seq[byte]](@"Plaintext"))
    check hex(cipher) == "bbf316e8d940af0ad3"

  test "classic: key=\"Wiki\", plaintext=\"pedia\"":
    let cipher = rc4(cast[seq[byte]](@"Wiki"), cast[seq[byte]](@"pedia"))
    check hex(cipher) == "1021bf0420"

  test "RFC 6229 KEY=0102030405, first 16 bytes of stream":
    let key = unhex("0102030405")
    let zero = newSeq[byte](16)
    let cipher = rc4(key, zero)
    check hex(cipher) == "b2396305f03dc027ccc3524a0a1118a8"

  test "encrypt/decrypt symmetry":
    let key = unhex("0102030405060708")
    let plain = cast[seq[byte]](@"Hello, RC4 round-trip test 12345")
    let cipher = rc4(key, plain)
    let back = rc4(key, cipher)
    check back == plain

  test "stateful streaming matches one-shot":
    let key = unhex("0102030405")
    let plain = cast[seq[byte]](@"abcdefghijklmnopqrstuvwxyz")
    let oneShot = rc4(key, plain)
    # Streaming: feed in two chunks.
    var c: Rc4Ctx
    c.initRc4(key)
    let part1 = c.apply(plain[0 ..< 10])
    let part2 = c.apply(plain[10 ..< plain.len])
    check (part1 & part2) == oneShot
