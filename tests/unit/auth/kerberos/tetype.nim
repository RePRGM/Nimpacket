## Kerberos ETYPE tests. The AES-CTS encryption is the tricky one;
## we check string-to-key against RFC 3962 test vectors.

import std/[unittest, strutils]
import msrpc/auth/kerberos/etype

proc hex(d: openArray[byte]): string =
  for b in d: result.add toHex(int(b), 2).toLowerAscii

suite "Kerberos string-to-key (RFC 3962 §6 vectors)":
  test "ETYPE=18, iter=1, password=\"password\" — full DK output":
    let pwd = cast[seq[byte]](@"password")
    let salt = cast[seq[byte]](@"ATHENA.MIT.EDUraeburn")
    let key = stringToKey(pwd, salt, EtypeAes256, iterations = 1)
    check key.len == 32
    check hex(key) ==
      "fe697b52bc0d3ce14432ba036a92e65bbb52280990a2fa27883998d72af30161"

  test "ETYPE=17, iter=1 produces 16-byte key (4226…)":
    let pwd = cast[seq[byte]](@"password")
    let salt = cast[seq[byte]](@"ATHENA.MIT.EDUraeburn")
    let key = stringToKey(pwd, salt, EtypeAes128, iterations = 1)
    check key.len == 16
    check hex(key) == "42263c6e89f4fc28b8df68ee09799f15"

suite "AES-CTS encryption":
  test "single-block input matches plain CBC":
    let key = newSeq[byte](32)   # all-zero AES-256 key
    let pt = newSeq[byte](16)    # one all-zero block
    let ct = aesCtsEncrypt(key, pt)
    check ct.len == 16
    # AES-256(00*32, 00*16) = dc95c078a2408989ad48a21492842087
    check hex(ct) == "dc95c078a2408989ad48a21492842087"

  test "non-aligned input produces same-length ciphertext":
    let key = newSeq[byte](32)
    var pt = newSeq[byte](24)    # 16 + 8 bytes
    for i in 0 ..< 24: pt[i] = byte(i)
    let ct = aesCtsEncrypt(key, pt)
    check ct.len == 24
