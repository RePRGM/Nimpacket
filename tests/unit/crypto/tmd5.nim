## RFC 1321 §A.5 test vectors.

import std/[unittest, strutils]
import msrpc/crypto/md5

proc hex(d: openArray[byte]): string =
  for b in d: result.add toHex(int(b), 2).toLowerAscii

suite "md5 (RFC 1321)":
  test "empty":
    check hex(md5(@[])) == "d41d8cd98f00b204e9800998ecf8427e"

  test "\"a\"":
    check hex(md5(cast[seq[byte]](@"a"))) == "0cc175b9c0f1b6a831c399e269772661"

  test "\"abc\"":
    check hex(md5(cast[seq[byte]](@"abc"))) == "900150983cd24fb0d6963f7d28e17f72"

  test "\"message digest\"":
    check hex(md5(cast[seq[byte]](@"message digest"))) ==
      "f96b697d7cb7938d525a2f31aaf161d0"

  test "alphabet a..z":
    check hex(md5(cast[seq[byte]](@"abcdefghijklmnopqrstuvwxyz"))) ==
      "c3fcd3d76192e4007dfb496cca67e13b"

  test "long alphanumeric":
    let msg = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    check hex(md5(cast[seq[byte]](@msg))) ==
      "d174ab98d277d9f5a5611c2c9f419d9f"

  test "80 digit string":
    let msg = "12345678901234567890123456789012345678901234567890123456789012345678901234567890"
    check hex(md5(cast[seq[byte]](@msg))) ==
      "57edf4a22be3c955ac49da2e2107b67a"
