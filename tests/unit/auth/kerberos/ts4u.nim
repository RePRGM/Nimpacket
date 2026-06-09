## MS-SFU S4U2self PA-FOR-USER builder tests.
##
## Golden values produced by impacket (getST path) for:
##   userName "victim", userRealm "CORP.LOCAL", NT_PRINCIPAL,
##   TGT session key 0102..10 (RC4), KERB_CHECKSUM_HMAC_MD5 (-138).

import std/[unittest, strutils]
import msrpc/auth/kerberos/s4u
import msrpc/auth/kerberos/messages

proc fromHex(s: string): seq[byte] =
  result = newSeq[byte](s.len div 2)
  for i in 0 ..< result.len:
    result[i] = byte(parseHexInt(s[2*i .. 2*i+1]))

proc toHex(d: openArray[byte]): string =
  for b in d: result.add toHex(int(b), 2).toLowerAscii

let sessionKey = fromHex("0102030405060708090a0b0c0d0e0f10")

suite "S4U checksum input":
  test "S4UByteArray = LE32(nametype) + names":
    let s4u = s4uByteArray(NtPrincipal, "victim", "CORP.LOCAL", "Kerberos")
    check toHex(s4u) == "0100000076696374696d434f52502e4c4f43414c4b65726265726f73"

suite "KERB_CHECKSUM_HMAC_MD5":
  test "matches impacket's checksum over the S4U byte array":
    let s4u = s4uByteArray(NtPrincipal, "victim", "CORP.LOCAL", "Kerberos")
    let chk = kerbChecksumHmacMd5(sessionKey, KerbNonKerbCksumSalt, s4u)
    check toHex(chk) == "964bfca2fd7d7af026ff32491962fde8"

suite "DER signed integer":
  test "negative checksum type -138 encodes as ff76":
    check toHex(derSignedInt(-138)) == "ff76"
  test "positive types encode minimally":
    check toHex(derSignedInt(16)) == "10"
    check toHex(derSignedInt(0)) == "00"

suite "PA-FOR-USER builder":
  test "byte-identical to impacket's PA-FOR-USER":
    let pa = buildPaForUser("victim", "CORP.LOCAL", sessionKey)
    check toHex(pa) ==
      "304da0133011a003020101a10a30081b0676696374696d" &
      "a10c1b0a434f52502e4c4f43414c" &
      "a21c301aa0040202ff76a1120410964bfca2fd7d7af026ff32491962fde8" &
      "a30a1b084b65726265726f73"
