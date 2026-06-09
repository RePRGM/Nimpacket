## MIT keytab (v2) reader/writer tests.
##
## The golden vector was hand-assembled per the documented keytab format and
## confirmed to parse byte-for-byte with impacket's keytab reader. It holds a
## single live entry:
##   principal : alice@EXAMPLE.COM  (NT_PRINCIPAL = 1)
##   key       : etype 18 (AES256), bytes 0x00..0x1f
##   kvno      : 5 (both the vno8 byte and the 4-byte trailer)
##   timestamp : 0x61000000

import std/[unittest, strutils]
import msrpc/auth/kerberos/keytab

const goldenHex =
  "0502" &                                   # file_format_version 0x0502
  "00000047" &                               # entry size = 71
  "0001" &                                   # num_components = 1
  "000b4558414d504c452e434f4d" &             # realm "EXAMPLE.COM"
  "0005616c696365" &                         # component "alice"
  "00000001" &                               # name_type = 1 (trails components)
  "61000000" &                               # timestamp
  "05" &                                     # vno8
  "0012" &                                   # keytype 18 (AES256)
  "0020000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" &  # key
  "00000005"                                 # uint32 kvno trailer = 5

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

let golden = fromHex(goldenHex)

suite "keytab v2 parse":
  let kt = parseKeytab(golden)

  test "one live entry":
    check kt.entries.len == 1
    check kt.entries[0].deleted == false

  test "principal with trailing name-type":
    let p = kt.entries[0].principal
    check p.nameType == 1
    check p.realm == "EXAMPLE.COM"
    check p.components == @["alice"]
    check p.prettyName == "alice@EXAMPLE.COM"

  test "key block":
    let e = kt.entries[0]
    check e.keytype == 18
    check e.key == toSeq0_31()
    check e.timestamp == 0x61000000'u32

  test "kvno prefers the 4-byte trailer":
    check kt.entries[0].vno8 == 5
    check kt.entries[0].kvno == 5

suite "keytab v2 encode":
  test "re-encode is byte-identical":
    check toHex(encodeKeytab(parseKeytab(golden))) == goldenHex

  test "built from scratch equals the golden keytab":
    var kt: Keytab
    kt.entries.add ktEntry(
      KtPrincipal(nameType: 1, realm: "EXAMPLE.COM", components: @["alice"]),
      keytype = 18, key = toSeq0_31(), timestamp = 0x61000000'u32, kvno = 5)
    check toHex(encodeKeytab(kt)) == goldenHex

  test "multi-entry round-trip":
    var kt: Keytab
    kt.entries.add ktEntry(
      KtPrincipal(nameType: 1, realm: "R", components: @["a"]),
      keytype = 17, key = toSeq0_31()[0 ..< 16], timestamp = 1, kvno = 2)
    kt.entries.add ktEntry(
      KtPrincipal(nameType: 2, realm: "R", components: @["host", "h.r"]),
      keytype = 18, key = toSeq0_31(), timestamp = 9, kvno = 300)   # >255: needs trailer
    let rt = parseKeytab(encodeKeytab(kt))
    check rt.entries.len == 2
    check rt.entries[1].principal.prettyName == "host/h.r@R"
    check rt.entries[1].kvno == 300
    check rt.entries[0].keytype == 17

suite "keytab rejects unsupported formats":
  test "version 1 is rejected":
    var v1 = golden
    v1[1] = 0x01
    expect KeytabError:
      discard parseKeytab(v1)

  test "truncated entry is rejected, not crashed":
    expect KeytabError:
      discard parseKeytab(golden[0 ..< 20])
