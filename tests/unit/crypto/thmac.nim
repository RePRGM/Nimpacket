## RFC 2202 §2 HMAC-MD5 vectors.

import std/[unittest, strutils]
import msrpc/crypto/hmac

proc hex(d: openArray[byte]): string =
  for b in d: result.add toHex(int(b), 2).toLowerAscii

proc unhex(s: string): seq[byte] =
  for i in countup(0, s.len - 1, 2):
    result.add byte(parseHexInt(s[i ..< i+2]))

suite "hmac-md5 (RFC 2202)":
  test "case 1: 16-byte 0x0b key, \"Hi There\"":
    let key = unhex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
    let msg = cast[seq[byte]](@"Hi There")
    check hex(hmacMd5(key, msg)) == "9294727a3638bb1c13f48ef8158bfc9d"

  test "case 2: key \"Jefe\", msg \"what do ya want for nothing?\"":
    let key = cast[seq[byte]](@"Jefe")
    let msg = cast[seq[byte]](@"what do ya want for nothing?")
    check hex(hmacMd5(key, msg)) == "750c783e6ab0b503eaa86e310a5db738"

  test "case 3: 16x0xaa key, 50x0xdd msg":
    let key = unhex("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
    var msg = newSeq[byte](50)
    for i in 0 ..< 50: msg[i] = 0xdd
    check hex(hmacMd5(key, msg)) == "56be34521d144c88dbb8c733f0e8b3f6"

  test "case 4: 25-byte key 01..19, 50x0xcd":
    let key = unhex("0102030405060708090a0b0c0d0e0f10111213141516171819")
    var msg = newSeq[byte](50)
    for i in 0 ..< 50: msg[i] = 0xcd
    check hex(hmacMd5(key, msg)) == "697eaf0aca3a3aea3a75164746ffaa79"

  test "case 6: 80-byte 0xaa key (longer than block)":
    var key = newSeq[byte](80)
    for i in 0 ..< 80: key[i] = 0xaa
    let msg = cast[seq[byte]](@"Test Using Larger Than Block-Size Key - Hash Key First")
    check hex(hmacMd5(key, msg)) == "6b1ab7fe4bd7bf8f0b62e6ce61b9d0cd"
