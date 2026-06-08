## NTLM MIC unit tests. We can't test against MS-NLMP §4.2 vectors
## because those don't include a MIC, so we verify the structural
## properties:
##   1. Without server MsvAvTimestamp: no MIC in the AUTHENTICATE
##      message (hasMic == false).
##   2. With server MsvAvTimestamp: AUTHENTICATE has a MIC, and the
##      MIC equals HMAC_MD5(ExportedSessionKey,
##        NEGOTIATE || CHALLENGE || AUTH_with_mic_zeroed).
##   3. The AV_PAIR list inside the NTLMv2 response carries
##      MsvAvFlags with bit 0x2 set.

import std/[unittest, strutils]
import msrpc/crypto/hmac
import msrpc/auth/ntlm/[messages, provider]

proc unhex(s: string): seq[byte] =
  for i in countup(0, s.len - 1, 2):
    result.add byte(parseHexInt(s[i ..< i+2]))

proc fakeChallenge(withTimestamp: bool): seq[byte] =
  var pairs = @[
    AvPair(id: MsvAvNbDomain,
            value: @[byte('D'), 0, byte('O'), 0, byte('M'), 0]),
    AvPair(id: MsvAvNbComputer,
            value: @[byte('S'), 0, byte('R'), 0, byte('V'), 0])]
  if withTimestamp:
    pairs.add AvPair(id: MsvAvTimestamp,
                      value: @[0x00'u8, 0x80, 0x3E, 0xD5,
                                0xDE, 0xAD, 0xBE, 0xEF])
  let ti = serialize(pairs)
  result = ChallengeMessage(
    flags: {NEGOTIATE_UNICODE, NEGOTIATE_NTLM,
            NEGOTIATE_EXTENDED_SESSIONSECURITY,
            NEGOTIATE_KEY_EXCH, NEGOTIATE_TARGET_INFO,
            NEGOTIATE_128},
    targetName: "DOM",
    serverChallenge: [0x01'u8, 0x23, 0x45, 0x67,
                       0x89, 0xab, 0xcd, 0xef],
    targetInfo: ti,
    hasVersion: false).build()

suite "ntlm MIC":
  test "no MIC when server doesn't send MsvAvTimestamp":
    let p = newNtlmProvider("Domain", "User", "Password")
    discard p.initialize("cifs/host")
    let auth = p.step(fakeChallenge(withTimestamp = false))
    let am = parseAuthenticate(auth)
    check (not am.hasMic)

  test "MIC present and correct when MsvAvTimestamp is in CHALLENGE":
    let p = newNtlmProvider("Domain", "User", "Password")
    let neg = p.initialize("cifs/host")
    let chal = fakeChallenge(withTimestamp = true)
    let auth = p.step(chal)
    let am = parseAuthenticate(auth, hasMic = true)
    check am.hasMic

    # Recompute MIC: HMAC_MD5(ExportedSessionKey,
    #   NEGOTIATE || CHALLENGE || AUTH_with_mic_zeroed).
    # Our fakeChallenge() doesn't set NEGOTIATE_VERSION, so after flag
    # intersection the AUTHENTICATE has no Version block and MIC is
    # at offset 64.
    var auth0 = auth
    const MicOffset = 64
    for i in 0 ..< 16: auth0[MicOffset + i] = 0
    var concat = newSeq[byte](neg.len + chal.len + auth0.len)
    var off = 0
    for b in neg: concat[off] = b; inc off
    for b in chal: concat[off] = b; inc off
    for b in auth0: concat[off] = b; inc off
    let expected = hmacMd5(p.exportedSessionKey, concat)
    for i in 0 ..< 16:
      check am.mic[i] == expected[i]

  test "MsvAvFlags bit 0x2 added to AV_PAIRs in NTLMv2 response":
    let p = newNtlmProvider("Domain", "User", "Password")
    discard p.initialize("cifs/host")
    let auth = p.step(fakeChallenge(withTimestamp = true))
    let am = parseAuthenticate(auth, hasMic = true)
    # The NTLMv2 response payload is NTProofStr(16) || temp.
    # temp = ResponseVersion(1) || HiResp(1) || Z(6) || Time(8) ||
    #        ClientChal(8) || Z(4) || TargetInfo || Z(4).
    # AV_PAIRs start at offset 16 + 1+1+6+8+8+4 = 44, end 4 bytes
    # before the response end (trailing Z(4)).
    doAssert am.ntResponse.len > 44 + 8
    let avBytes = am.ntResponse[44 ..< am.ntResponse.len - 4]
    let avs = parseAvPairs(avBytes)
    var found = false
    for pair in avs:
      if pair.id == MsvAvFlags and pair.value.len == 4:
        let v = uint32(pair.value[0]) or
                (uint32(pair.value[1]) shl 8) or
                (uint32(pair.value[2]) shl 16) or
                (uint32(pair.value[3]) shl 24)
        check (v and 0x2'u32) == 0x2
        found = true
    check found
