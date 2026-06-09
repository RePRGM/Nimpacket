## MS-SFU S4U2self PA-FOR-USER builder tests.
##
## Golden values produced by impacket (getST path) for:
##   userName "victim", userRealm "CORP.LOCAL", NT_PRINCIPAL,
##   TGT session key 0102..10 (RC4), KERB_CHECKSUM_HMAC_MD5 (-138).

import std/[unittest, strutils]
import msrpc/auth/kerberos/s4u
import msrpc/auth/kerberos/messages
import msrpc/auth/kerberos/tgsreq

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

suite "KDC-options flag packing":
  test "bit positions map MSB-first into the 32-bit field":
    check kdcOptionFlags([KdcOptForwardable, KdcOptRenewable, KdcOptCanonicalize]) ==
      [0x40'u8, 0x81, 0x00, 0x00]
    check kdcOptionFlags([KdcOptForwardable, KdcOptRenewable,
                          KdcOptCnameInAddlTkt, KdcOptCanonicalize]) ==
      [0x40'u8, 0x83, 0x00, 0x00]

const fakeApReq = @[0x6e'u8, 0x03, 0x30, 0x01, 0x00]            # opaque AP-REQ
const fakeEvidence = @[0x61'u8, 0x05, 0x30, 0x03, 0x02, 0x01, 0x05]  # opaque Ticket

suite "S4U2self request":
  let req = buildS4U2self("CORP.LOCAL", ["host", "web.corp.local"],
                          "victim", "CORP.LOCAL", sessionKey,
                          nonce = 0x11111111'u32, etypes = [0x17'u32],
                          till = "20260601000000Z", apReq = fakeApReq)
  let h = toHex(req)

  test "is a TGS-REQ (msg-type 12)":
    check req[0] == 0x6C'u8
    check "a20302010c" in h

  test "carries a PA-FOR-USER padata (type 129) with the checksum":
    check "a1040202008" in h            # [1] INTEGER 129 (0x0081)
    check "964bfca2fd7d7af026ff32491962fde8" in h

  test "kdc-options = forwardable+renewable+canonicalize, no addl-tkt":
    check "03050040810000" in h
    check "03050040830000" notin h

  test "targets the service's own principal (host/web.corp.local)":
    check "686f7374" in h                        # "host"
    check "7765622e636f72702e6c6f63616c" in h    # "web.corp.local"

suite "S4U2proxy request":
  let req = buildS4U2proxy("CORP.LOCAL", ["cifs", "file.corp.local"],
                           fakeEvidence,
                           nonce = 0x22222222'u32, etypes = [0x17'u32],
                           till = "20260601000000Z", apReq = fakeApReq)
  let h = toHex(req)

  test "is a TGS-REQ (msg-type 12)":
    check req[0] == 0x6C'u8
    check "a20302010c" in h

  test "sets cname-in-addl-tkt in kdc-options":
    check "03050040830000" in h

  test "places the evidence ticket in additional-tickets [11]":
    # [11] (0xab) -> SEQUENCE (0x30) -> the evidence Ticket bytes
    check "ab09300761053003020105" in h

  test "carries no PA-FOR-USER":
    check "964bfca2fd7d7af026ff32491962fde8" notin h
