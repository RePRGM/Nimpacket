## RFC 4493 §4 / NIST CAVP test vectors for AES-128-CMAC.

import std/[unittest, strutils]
import msrpc/crypto/aes_cmac

proc hex(d: openArray[byte]): string =
  for b in d: result.add toHex(int(b), 2).toLowerAscii

proc unhex(s: string): seq[byte] =
  var t = ""
  for c in s:
    if c != ' ': t.add c
  for i in countup(0, t.len - 1, 2):
    result.add byte(parseHexInt(t[i ..< i+2]))

suite "AES-128-CMAC (RFC 4493 §4)":
  const Key = "2b7e1516 28aed2a6 abf71588 09cf4f3c"

  test "empty message":
    check hex(aesCmac128(unhex(Key), @[])) ==
      "bb1d6929e95937287fa37d129b756746"

  test "16-byte message (M1)":
    let m = unhex("6bc1bee2 2e409f96 e93d7e11 7393172a")
    check hex(aesCmac128(unhex(Key), m)) ==
      "070a16b46b4d4144f79bdd9dd04a287c"

  test "40-byte message (M2)":
    let m = unhex(
      "6bc1bee2 2e409f96 e93d7e11 7393172a" &
      "ae2d8a57 1e03ac9c 9eb76fac 45af8e51" &
      "30c81c46 a35ce411")
    check hex(aesCmac128(unhex(Key), m)) ==
      "dfa66747de9ae63030ca32611497c827"

  test "64-byte message (M3)":
    let m = unhex(
      "6bc1bee2 2e409f96 e93d7e11 7393172a" &
      "ae2d8a57 1e03ac9c 9eb76fac 45af8e51" &
      "30c81c46 a35ce411 e5fbc119 1a0a52ef" &
      "f69f2445 df4f9b17 ad2b417b e66c3710")
    check hex(aesCmac128(unhex(Key), m)) ==
      "51f0bebf7e3b9d92fc49741779363cfe"
