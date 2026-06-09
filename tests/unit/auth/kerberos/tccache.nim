## MIT credential cache (v4) reader/writer tests.
##
## The golden vector below was produced by impacket's
## ``impacket.krb5.ccache`` for a deterministic cache:
##   default principal : alice@EXAMPLE.COM            (NT_PRINCIPAL = 1)
##   one credential to : krbtgt/EXAMPLE.COM@EXAMPLE.COM (NT_SRV_INST = 2)
##   session key       : etype 18 (AES256), bytes 0x00..0x1f
##   ticket            : 0x61 0x07 "TICKET!"
## Parsing it and re-encoding must reproduce the exact same bytes, which
## pins our layout to impacket's (and therefore to klist/kinit).

import std/[unittest, strutils]
import msrpc/auth/kerberos/ccache

const goldenHex =
  "0504000c00010008ffffffff00000000" &
  "0000000100000001" & "0000000b4558414d504c452e434f4d" & "00000005616c696365" &
  "0000000100000001" & "0000000b4558414d504c452e434f4d" & "00000005616c696365" &
  "0000000200000002" & "0000000b4558414d504c452e434f4d" &
    "000000066b72627467740000000b4558414d504c452e434f4d" &
  "001200000020" & "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" &
  "61000000610000006100800061100000" & "00" & "40e10000" &
  "00000000" & "00000000" &
  "0000000961075449434b455421" & "00000000"

proc fromHex(s: string): seq[byte] =
  doAssert s.len mod 2 == 0
  result = newSeq[byte](s.len div 2)
  for i in 0 ..< result.len:
    result[i] = byte(parseHexInt(s[2*i .. 2*i+1]))

proc toHex(d: openArray[byte]): string =
  for b in d: result.add toHex(int(b), 2).toLowerAscii

proc toSeq0_31(): seq[byte] =
  result = newSeq[byte](32)
  for i in 0 ..< 32: result[i] = byte(i)

proc sb(s: string): seq[byte] =
  result = newSeq[byte](s.len)
  for i, c in s: result[i] = byte(c)

let golden = fromHex(goldenHex)

suite "ccache v4 parse":
  let cc = parseCcache(golden)

  test "default principal":
    check cc.defaultPrincipal.nameType == 1
    check cc.defaultPrincipal.realm == "EXAMPLE.COM"
    check cc.defaultPrincipal.components == @["alice"]
    check cc.defaultPrincipal.prettyName == "alice@EXAMPLE.COM"

  test "single header (DeltaTime), preserved verbatim":
    check cc.headers.len == 1
    check cc.headers[0].tag == HdrTagDeltaTime
    check cc.headers[0].data == @[0xff'u8, 0xff, 0xff, 0xff, 0, 0, 0, 0]

  test "one credential to the TGT":
    check cc.credentials.len == 1
    let c = cc.credentials[0]
    check c.client.prettyName == "alice@EXAMPLE.COM"
    check c.server.nameType == 2
    check c.server.prettyName == "krbtgt/EXAMPLE.COM@EXAMPLE.COM"

  test "session key block":
    let k = cc.credentials[0].key
    check k.keytype == 18
    check k.etype == 0
    check k.key.len == 32
    check k.key == toSeq0_31()

  test "times, flags, skey":
    let c = cc.credentials[0]
    check c.times.authtime == 0x61000000'u32
    check c.times.endtime == 0x61008000'u32
    check c.times.renewTill == 0x61100000'u32
    check c.tktFlags == 0x40e10000'u32
    check c.isSkey == false

  test "ticket and absent second ticket":
    let c = cc.credentials[0]
    check toHex(c.ticket) == "61075449434b455421"   # 0x61 0x07 "TICKET!"
    check c.secondTicket.len == 0
    check c.addresses.len == 0
    check c.authData.len == 0

suite "ccache v4 encode":
  test "re-encode is byte-identical to impacket's output":
    let cc = parseCcache(golden)
    check toHex(encodeCcache(cc)) == goldenHex

  test "built from scratch equals the golden cache":
    var cc = defaultCcache(CcPrincipal(nameType: 1, realm: "EXAMPLE.COM",
                                       components: @["alice"]))
    cc.credentials.add CcCredential(
      client: cc.defaultPrincipal,
      server: CcPrincipal(nameType: 2, realm: "EXAMPLE.COM",
                          components: @["krbtgt", "EXAMPLE.COM"]),
      key: CcKeyBlock(keytype: 18, etype: 0, key: toSeq0_31()),
      times: CcTimes(authtime: 0x61000000'u32, starttime: 0x61000000'u32,
                     endtime: 0x61008000'u32, renewTill: 0x61100000'u32),
      isSkey: false,
      tktFlags: 0x40e10000'u32,
      ticket: @[0x61'u8, 0x07] & sb("TICKET!"),
      secondTicket: @[])
    check toHex(encodeCcache(cc)) == goldenHex

  test "round-trips an empty cache":
    let cc = defaultCcache(CcPrincipal(nameType: 1, realm: "R", components: @["u"]))
    check parseCcache(encodeCcache(cc)).defaultPrincipal.prettyName == "u@R"

suite "ccache rejects unsupported formats":
  test "version 3 is rejected with a clear error":
    var v3 = golden
    v3[1] = 0x03    # magic 0x0503
    expect CcacheError:
      discard parseCcache(v3)

  test "truncated input is rejected, not crashed":
    expect CcacheError:
      discard parseCcache(golden[0 ..< 40])
