## AES-128-CCM tests. Vectors from RFC 3610 §8.

import std/[unittest, strutils]
import msrpc/crypto/aes_ccm

proc hex(d: openArray[byte]): string =
  for b in d: result.add toHex(int(b), 2).toLowerAscii

proc unhex(s: string): seq[byte] =
  var t = ""
  for c in s:
    if c != ' ': t.add c
  for i in countup(0, t.len - 1, 2):
    result.add byte(parseHexInt(t[i ..< i+2]))

suite "AES-128-CCM (RFC 3610)":
  # Packet Vector #1 from RFC 3610.
  test "PV#1: short message, 13-byte nonce, 8-byte tag":
    let key   = unhex("c0c1c2c3c4c5c6c7 c8c9cacbcccdcecf")
    let nonce = unhex("00000003 020100 a0a1a2a3a4a5")
    let aad   = unhex("0001020304050607")
    let pt    = unhex("08090a0b0c0d0e0f 1011121314151617" &
                       "18191a1b1c1d1e")
    let (ct, tag) = ccmEncrypt(key, nonce, aad, pt, tagLen = 8)
    check hex(ct) ==
      "588c979a61c663d2f066d0c2c0f989806d5f6b61dac384"
    check hex(tag) == "17e8d12cfdf926e0"
    # Round-trip decrypt
    let (pt2, ok) = ccmDecrypt(key, nonce, aad, ct, tag)
    check ok
    check pt2 == pt

  test "tampered ciphertext fails verification":
    let key   = unhex("c0c1c2c3c4c5c6c7c8c9cacbcccdcecf")
    let nonce = unhex("00000003020100a0a1a2a3a4a5")
    let aad   = unhex("0001020304050607")
    let pt    = unhex("08090a0b0c0d0e0f101112131415161718191a1b1c1d1e")
    let (ct, tag) = ccmEncrypt(key, nonce, aad, pt, tagLen = 8)
    var ctBad = ct
    ctBad[0] = ctBad[0] xor 0x01
    let (pt2, ok) = ccmDecrypt(key, nonce, aad, ctBad, tag)
    check (not ok)
    check pt2.len == 0
