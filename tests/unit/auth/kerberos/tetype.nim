## Kerberos ETYPE tests. The AES-CTS encryption is the tricky one;
## we check string-to-key against RFC 3962 test vectors.

import std/[unittest, strutils]
import msrpc/auth/kerberos/etype

proc hex(d: openArray[byte]): string =
  for b in d: result.add toHex(int(b), 2).toLowerAscii

suite "Kerberos string-to-key (RFC 3962 §6 vectors)":
  test "ETYPE=18, iter=1, password=\"password\", salt=\"ATHENA.MIT.EDUraeburn\"":
    # Vector from RFC 3962 §6: iter=1 → tkey first 32 bytes
    let pwd = cast[seq[byte]](@"password")
    let salt = cast[seq[byte]](@"ATHENA.MIT.EDUraeburn")
    let tkey = stringToKey(pwd, salt, EtypeAes256, iterations = 1)
    check tkey.len == 32
    check hex(tkey) ==
      "cdedb5281bb2f801565a1122b25635150ad1f7a04bb9f3a333ecc0e2e1f70837"

  test "ETYPE=17 produces 16-byte output with iter=1":
    # The RFC 3962 §6 vector for the FINAL AES-128 key is
    # "42263c6e89f4fc28b8df68ee09799f15", but that's the post-DK
    # result (DK applies AES-CTS to derive subkey usages). v0 of our
    # stringToKey returns the pre-DK tkey; DK is a follow-up.
    let pwd = cast[seq[byte]](@"password")
    let salt = cast[seq[byte]](@"ATHENA.MIT.EDUraeburn")
    let tkey = stringToKey(pwd, salt, EtypeAes128, iterations = 1)
    check tkey.len == 16
    # Verify determinism + matches first 16 bytes of AES-256 tkey
    # (since both are PBKDF2-HMAC-SHA1 streams with same inputs).
    let tkey256 = stringToKey(pwd, salt, EtypeAes256, iterations = 1)
    check tkey256[0 ..< 16] == tkey

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
