## MS-PAC container + simple-buffer tests.
##
## Golden PAC built and verified with impacket (impacket.krb5.pac). It holds
## three buffers in order:
##   type 10 (CLIENT_INFO)     : ClientId 0x61000000, name "alice"
##   type 6  (SERVER_CHECKSUM) : sig type 16, 12-byte signature 0x00..0x0b
##   type 7  (KDC_CHECKSUM)    : sig type 16, 12-byte signature 0x0c..0x17
## Offsets are 8-aligned (56 / 80 / 96), so re-encoding must reproduce the
## exact bytes — pinning our container layout to impacket's.

import std/[unittest, strutils]
import msrpc/auth/kerberos/pac

const goldenHex =
  "03000000" & "00000000" &                       # cBuffers=3, Version=0
  "0a000000" & "14000000" & "3800000000000000" &  # CLIENT_INFO  size 20 @56
  "06000000" & "10000000" & "5000000000000000" &  # SERVER_CKSUM size 16 @80
  "07000000" & "10000000" & "6000000000000000" &  # KDC_CKSUM    size 16 @96
  "0000006100000000" & "0a00" & "61006c00690063006500" & "00000000" &  # @56 client info (10-byte name + 4 pad)
  "10000000" & "000102030405060708090a0b" &       # @80 server checksum
  "10000000" & "0c0d0e0f1011121314151617"         # @96 kdc checksum

proc fromHex(s: string): seq[byte] =
  doAssert s.len mod 2 == 0
  result = newSeq[byte](s.len div 2)
  for i in 0 ..< result.len:
    result[i] = byte(parseHexInt(s[2*i .. 2*i+1]))

proc toHex(d: openArray[byte]): string =
  for b in d: result.add toHex(int(b), 2).toLowerAscii

let golden = fromHex(goldenHex)

suite "PAC container parse":
  let pac = parsePac(golden)

  test "header and buffer descriptors":
    check pac.version == 0
    check pac.buffers.len == 3
    check pac.buffers[0].ulType == PacClientInfo
    check pac.buffers[1].ulType == PacServerChecksum
    check pac.buffers[2].ulType == PacKdcChecksum

  test "findBuffer / hasBuffer":
    check pac.hasBuffer(PacClientInfo)
    check pac.hasBuffer(PacKdcChecksum)
    check not pac.hasBuffer(PacLogonInfo)
    check pac.findBuffer(PacLogonInfo).len == 0
    check toHex(pac.findBuffer(PacServerChecksum)) == "10000000000102030405060708090a0b"

  test "re-encode is byte-identical to impacket's PAC":
    check toHex(encodePac(pac)) == goldenHex

suite "PAC simple buffers":
  let pac = parsePac(golden)

  test "PAC_CLIENT_INFO decodes the account name":
    let ci = parseClientInfo(pac.findBuffer(PacClientInfo))
    check ci.clientId == 0x61000000'u64
    check ci.name == "alice"

  test "PAC_CLIENT_INFO round-trips":
    let ci = parseClientInfo(pac.findBuffer(PacClientInfo))
    check encodeClientInfo(ci) == pac.findBuffer(PacClientInfo)

  test "PAC_SIGNATURE_DATA splits type and signature":
    let s = parseSignature(pac.findBuffer(PacServerChecksum))
    check s.signatureType == 16
    check s.signature.len == 12
    check toHex(s.signature) == "000102030405060708090a0b"

  test "PAC_SIGNATURE_DATA round-trips both checksums":
    for t in [PacServerChecksum, PacKdcChecksum]:
      check encodeSignature(parseSignature(pac.findBuffer(t))) == pac.findBuffer(t)

suite "PAC rejects malformed input":
  test "buffer offset past end is rejected":
    var bad = golden
    bad[16] = 0xff   # corrupt the first descriptor's offset low byte
    expect PacError:
      discard parsePac(bad)

  test "truncated header is rejected, not crashed":
    expect PacError:
      discard parsePac(golden[0 ..< 6])
