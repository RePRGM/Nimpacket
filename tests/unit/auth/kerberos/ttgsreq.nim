import std/[unittest, strutils, times]
import msrpc/auth/kerberos/[rc4, apreq, tgsreq]

proc hex(d: openArray[byte]): string =
  for b in d: result.add toHex(int(b), 2).toLowerAscii

suite "Kerberos TGS-REQ":
  test "outer tag is [APPLICATION 12]":
    let sk = rc4HmacStringToKey("Password")
    let ticket = @[0x61'u8, 0x02, 0x30, 0x00]
    let ap = buildApReq(sk, ticket, "EX.COM", "u", fromUnix(1))
    let tgs = buildTgsReq("EX.COM", "cifs", "dc01.ex.com",
                           nonce = 0x33333333'u32,
                           etypes = [EtypeRc4Hmac],
                           till = "20260601000000Z",
                           apReq = ap)
    check tgs[0] == 0x6C'u8

  test "TGS-REQ has msg-type 12":
    let sk = rc4HmacStringToKey("Password")
    let ticket = @[0x61'u8, 0x02, 0x30, 0x00]
    let ap = buildApReq(sk, ticket, "EX.COM", "u", fromUnix(1))
    let tgs = buildTgsReq("EX.COM", "host", "srv.ex.com",
                           nonce = 0x44444444'u32,
                           etypes = [EtypeRc4Hmac],
                           till = "20260601000000Z",
                           apReq = ap)
    # msg-type in field [2] of the inner SEQUENCE — look for "a2 03 02 01 0c"
    check "a20302010c" in hex(tgs)
