## RFC 3962 test vectors for string-to-key + DK and a sanity check
## that AES-CTS encrypt/decrypt round-trip.

import std/[unittest, strutils]
import msrpc/auth/kerberos/etype
import msrpc/crypto/rand

proc h(d: openArray[byte]): string =
  for b in d: result.add toHex(int(b), 2).toLowerAscii

proc str(s: string): seq[byte] =
  result = newSeq[byte](s.len)
  for i, c in s: result[i] = byte(c)

proc unhex(s: string): seq[byte] =
  doAssert s.len mod 2 == 0
  result = newSeq[byte](s.len div 2)
  for i in 0 ..< result.len:
    result[i] = byte(parseHexInt(s[2*i .. 2*i+1]))

suite "RFC 3962 AES-128 stringToKey":
  test "iter=1 password=\"password\" salt=\"ATHENA.MIT.EDUraeburn\"":
    let k = stringToKey(str("password"), str("ATHENA.MIT.EDUraeburn"),
                        EtypeAes128, iterations = 1)
    check h(k) == "42263c6e89f4fc28b8df68ee09799f15"

  test "iter=2 password=\"password\" salt=\"ATHENA.MIT.EDUraeburn\"":
    let k = stringToKey(str("password"), str("ATHENA.MIT.EDUraeburn"),
                        EtypeAes128, iterations = 2)
    check h(k) == "c651bf29e2300ac27fa469d693bdda13"

  test "iter=1200 password=\"password\" salt=\"ATHENA.MIT.EDUraeburn\"":
    let k = stringToKey(str("password"), str("ATHENA.MIT.EDUraeburn"),
                        EtypeAes128, iterations = 1200)
    check h(k) == "4c01cd46d632d01e6dbe230a01ed642a"

suite "RFC 3962 AES-256 stringToKey":
  test "iter=1 password=\"password\" salt=\"ATHENA.MIT.EDUraeburn\"":
    let k = stringToKey(str("password"), str("ATHENA.MIT.EDUraeburn"),
                        EtypeAes256, iterations = 1)
    check h(k) == "fe697b52bc0d3ce14432ba036a92e65bbb52280990a2fa27883998d72af30161"

  test "iter=1200 password=\"password\" salt=\"ATHENA.MIT.EDUraeburn\"":
    let k = stringToKey(str("password"), str("ATHENA.MIT.EDUraeburn"),
                        EtypeAes256, iterations = 1200)
    check h(k) == "55a6ac740ad17b4846941051e1e8b0a7548d93b0ab30a8bc3ff16280382b8c2a"

suite "AES-CTS round-trip":
  test "encrypt then decrypt returns plaintext (AES-128, 17 bytes)":
    let key = unhex("00112233445566778899aabbccddeeff")
    let pt = unhex("0102030405060708090a0b0c0d0e0f1011")
    let ct = aesCtsEncrypt(key, pt)
    check ct.len == pt.len
    let rec = aesCtsDecrypt(key, ct)
    check rec == pt

  test "encrypt then decrypt returns plaintext (AES-128, 32 bytes)":
    let key = unhex("00112233445566778899aabbccddeeff")
    var pt = newSeq[byte](32)
    let r = randomBytes(32)
    for i in 0 ..< 32: pt[i] = r[i]
    let ct = aesCtsEncrypt(key, pt)
    let rec = aesCtsDecrypt(key, ct)
    check rec == pt

  test "encrypt then decrypt returns plaintext (AES-256, 50 bytes)":
    let key = unhex(
      "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")
    let r = randomBytes(50)
    let ct = aesCtsEncrypt(key, r)
    let rec = aesCtsDecrypt(key, ct)
    check rec == r
