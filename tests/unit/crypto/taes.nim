## FIPS 197 Appendix B / C known-answer tests.

import std/[unittest, strutils]
import msrpc/crypto/aes

proc hex(d: openArray[byte]): string =
  for b in d: result.add toHex(int(b), 2).toLowerAscii

proc unhex(s: string): seq[byte] =
  var t = ""
  for c in s:
    if c != ' ': t.add c
  for i in countup(0, t.len - 1, 2):
    result.add byte(parseHexInt(t[i ..< i+2]))

suite "aes-128 (FIPS 197 Appendix B)":
  test "key=000102030405060708090a0b0c0d0e0f, pt=00112233445566778899aabbccddeeff":
    let key = unhex("000102030405060708090a0b0c0d0e0f")
    let pt = unhex("00112233445566778899aabbccddeeff")
    check hex(aes128Encrypt(key, pt)) == "69c4e0d86a7b0430d8cdb78070b4c55a"

suite "aes-256 (FIPS 197 Appendix C.3)":
  test "key=000102...1f, pt=00112233...eeff":
    let key = unhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
    let pt = unhex("00112233445566778899aabbccddeeff")
    check hex(aes256Encrypt(key, pt)) == "8ea2b7ca516745bfeafc49904b496089"

suite "aes-256 (NIST SP 800-38A all-zeroes)":
  test "key=00*32, pt=00*16":
    var key = newSeq[byte](32)
    var pt = newSeq[byte](16)
    check hex(aes256Encrypt(key, pt)) == "dc95c078a2408989ad48a21492842087"
