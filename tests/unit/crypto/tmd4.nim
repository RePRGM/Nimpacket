## RFC 1320 §A.5 test vectors.

import std/[unittest, strutils]
import msrpc/crypto/md4

proc hex(d: openArray[byte]): string =
  for b in d: result.add toHex(int(b), 2).toLowerAscii

suite "md4 (RFC 1320)":
  test "empty":
    check hex(md4(@[])) == "31d6cfe0d16ae931b73c59d7e0c089c0"

  test "\"a\"":
    check hex(md4(cast[seq[byte]](@"a"))) == "bde52cb31de33e46245e05fbdbd6fb24"

  test "\"abc\"":
    check hex(md4(cast[seq[byte]](@"abc"))) == "a448017aaf21d8525fc10ae87aa6729d"

  test "\"message digest\"":
    check hex(md4(cast[seq[byte]](@"message digest"))) ==
      "d9130a8164549fe818874806e1c7014b"

  test "alphabet a..z":
    check hex(md4(cast[seq[byte]](@"abcdefghijklmnopqrstuvwxyz"))) ==
      "d79e1c308aa5bbcdeea8ed63df412da9"

  test "long alphanumeric":
    let msg = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    check hex(md4(cast[seq[byte]](@msg))) ==
      "043f8582f241db351ce627e153e7f0e4"

  test "80 digit string":
    let msg = "12345678901234567890123456789012345678901234567890123456789012345678901234567890"
    check hex(md4(cast[seq[byte]](@msg))) ==
      "e33b4ddc9c38f2199c3e7b164fcc0536"
