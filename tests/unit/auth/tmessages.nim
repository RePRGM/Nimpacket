## NTLM message wire-format tests.
##
## We check:
##   1. Build then parse a round-trip for each of NEGOTIATE/CHALLENGE/AUTH.
##   2. NEGOTIATE flag set <-> u32 mask round-trip.
##   3. AV_PAIR list serialize/parse with EOL handling.
##   4. CHALLENGE built with the MS-NLMP §4.2.2 example values reproduces
##      the documented Server Challenge bytes.

import std/[unittest, strutils]
import msrpc/auth/ntlm/messages

proc hex(d: openArray[byte]): string =
  for b in d: result.add toHex(int(b), 2).toLowerAscii

suite "ntlm flags":
  test "flag set <-> u32":
    let flags: NtlmFlags = {NEGOTIATE_UNICODE, NEGOTIATE_NTLM, NEGOTIATE_VERSION,
                            NEGOTIATE_KEY_EXCH, NEGOTIATE_128}
    let mask = toU32(flags)
    let expected =
      (1'u32 shl 0) or (1'u32 shl 9) or (1'u32 shl 25) or
      (1'u32 shl 29) or (1'u32 shl 30)
    check mask == expected
    check fromU32(mask) == flags

  test "reserved bits are dropped":
    # bit 3 is reserved — set the raw mask and verify fromU32 strips it.
    let raw = (1'u32 shl 3) or (1'u32 shl 0)
    check fromU32(raw) == {NEGOTIATE_UNICODE}

suite "ntlm av_pairs":
  test "serialize / parse roundtrip with EOL":
    let pairs = @[
      AvPair(id: MsvAvNbDomain, value: @[0x44'u8, 0x00, 0x4f]),  # "D\0O"
      AvPair(id: MsvAvNbComputer, value: @[0x53'u8, 0x00])]
    let bytes = serialize(pairs)
    # 4 (hdr) + 3 + 4 (hdr) + 2 + 4 (eol) = 17
    check bytes.len == 17
    let parsed = parseAvPairs(bytes)
    check parsed.len == 2
    check parsed[0].id == MsvAvNbDomain
    check parsed[0].value == @[0x44'u8, 0x00, 0x4f]
    check parsed[1].id == MsvAvNbComputer
    check parsed[1].value == @[0x53'u8, 0x00]

  test "empty list still terminates with EOL":
    let bytes = serialize([])
    check bytes == @[0'u8, 0, 0, 0]
    check parseAvPairs(bytes).len == 0

suite "ntlm NEGOTIATE":
  test "build then parse round-trip":
    let m = NegotiateMessage(
      flags: {NEGOTIATE_UNICODE, NEGOTIATE_NTLM, NEGOTIATE_OEM_DOMAIN_SUPPLIED},
      domain: "DOM",
      workstation: "WS",
      hasVersion: false)
    let bytes = m.build()
    # Signature first 8 bytes
    check bytes[0..7] == @NtlmSignatureBytes
    # MessageType = 1
    check bytes[8..11] == @[1'u8, 0, 0, 0]
    let p = parseNegotiate(bytes)
    check p.flags == m.flags
    check p.domain == m.domain
    check p.workstation == m.workstation

  test "with version flag":
    let m = NegotiateMessage(
      flags: {NEGOTIATE_UNICODE, NEGOTIATE_NTLM, NEGOTIATE_VERSION},
      hasVersion: true,
      version: DefaultVersion)
    let bytes = m.build()
    let p = parseNegotiate(bytes)
    check p.hasVersion
    check p.version.productBuild == 7600

suite "ntlm CHALLENGE":
  # MS-NLMP §4.2.2 sample server challenge.
  const sampleChallenge: array[8, byte] =
    [0x01'u8, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]

  test "build then parse round-trip":
    let m = ChallengeMessage(
      flags: {NEGOTIATE_UNICODE, NEGOTIATE_NTLM, NEGOTIATE_TARGET_INFO,
              TARGET_TYPE_SERVER},
      targetName: "Server",
      serverChallenge: sampleChallenge,
      targetInfo: serialize(@[
        AvPair(id: MsvAvNbDomain, value: @[0x44'u8, 0x00])]),
      hasVersion: false)
    let bytes = m.build()
    check bytes[8..11] == @[2'u8, 0, 0, 0]   # type=2
    let p = parseChallenge(bytes)
    check p.flags == m.flags
    check p.targetName == "Server"
    check p.serverChallenge == sampleChallenge
    let pairs = parseAvPairs(p.targetInfo)
    check pairs.len == 1
    check pairs[0].id == MsvAvNbDomain

suite "ntlm AUTHENTICATE":
  test "build then parse round-trip":
    let m = AuthenticateMessage(
      flags: {NEGOTIATE_UNICODE, NEGOTIATE_NTLM},
      lmResponse: @[0x00'u8],
      ntResponse: @[0x11'u8, 0x22, 0x33, 0x44],
      domain: "Domain",
      user: "User",
      workstation: "WS01",
      encryptedRandomSessionKey: @[0xAA'u8, 0xBB, 0xCC, 0xDD],
      hasVersion: false,
      hasMic: false)
    let bytes = m.build()
    check bytes[0..7] == @NtlmSignatureBytes
    check bytes[8..11] == @[3'u8, 0, 0, 0]   # type=3
    let p = parseAuthenticate(bytes)
    check p.flags == m.flags
    check p.lmResponse == m.lmResponse
    check p.ntResponse == m.ntResponse
    check p.domain == "Domain"
    check p.user == "User"
    check p.workstation == "WS01"
    check p.encryptedRandomSessionKey == m.encryptedRandomSessionKey

  test "with MIC":
    var m = AuthenticateMessage(
      flags: {NEGOTIATE_UNICODE},
      user: "u",
      hasMic: true)
    for i in 0 .. 15: m.mic[i] = byte(i)
    let bytes = m.build()
    let p = parseAuthenticate(bytes, hasMic = true)
    check p.hasMic
    check p.mic == m.mic
