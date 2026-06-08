## Provider tests: walk the AuthProvider through initialize / step using
## a self-built CHALLENGE message and confirm the AUTHENTICATE bytes
## parse back correctly and the session keys derive.

import std/unittest
import msrpc/auth/ntlm/[messages, provider]
import msrpc/rpc/auth as rpcauth

suite "ntlm provider":
  test "initialize emits a valid NEGOTIATE":
    let p = newNtlmProvider("DOM", "alice", "secret")
    let n = p.initialize("cifs/server")
    check parseNegotiate(n).flags.contains NEGOTIATE_NTLM
    check p.state == asContinue
    check p.targetSpn == "cifs/server"

  test "step produces an AUTHENTICATE that round-trips":
    let p = newNtlmProvider("Domain", "User", "Password")
    discard p.initialize("host/srv")

    # Mock CHALLENGE message we'd receive from the server.
    let cm = ChallengeMessage(
      flags: {NEGOTIATE_UNICODE, NEGOTIATE_NTLM,
              NEGOTIATE_EXTENDED_SESSIONSECURITY, NEGOTIATE_TARGET_INFO,
              NEGOTIATE_KEY_EXCH, NEGOTIATE_128, NEGOTIATE_SEAL,
              NEGOTIATE_SIGN, NEGOTIATE_ALWAYS_SIGN, TARGET_TYPE_SERVER},
      targetName: "SERVER",
      serverChallenge: [0x01'u8, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef],
      targetInfo: serialize(@[
        AvPair(id: MsvAvNbDomain, value: @[0x44'u8, 0x00, 0x4f, 0x00, 0x4d, 0x00])]),
      hasVersion: false)
    let challengeBytes = cm.build()

    let auth = p.step(challengeBytes)
    let parsed = parseAuthenticate(auth)
    check parsed.user == "User"
    check parsed.domain == "Domain"
    check parsed.ntResponse.len > 0
    # NTLMv2 NtChallengeResponse always begins with the 16-byte NTProofStr.
    check parsed.ntResponse.len >= 16
    check parsed.encryptedRandomSessionKey.len == 16
    check p.state == asEstablished
    check p.session != nil

  test "session is wired up: signOutgoing works after auth":
    let p = newNtlmProvider("D", "U", "P")
    discard p.initialize("h")
    let cm = ChallengeMessage(
      flags: {NEGOTIATE_UNICODE, NEGOTIATE_NTLM,
              NEGOTIATE_EXTENDED_SESSIONSECURITY,
              NEGOTIATE_KEY_EXCH, NEGOTIATE_128},
      serverChallenge: [0xAA'u8, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22],
      targetInfo: @[],
      hasVersion: false)
    discard p.step(cm.build())
    let sig = p.sign(@[0xCA'u8, 0xFE, 0xBA, 0xBE])
    check sig.len == 16
    check sig[0..3] == @[0x01'u8, 0, 0, 0]    # sign version
    # Two signs in a row produce different sigs (seq# advanced).
    let sig2 = p.sign(@[0xCA'u8, 0xFE, 0xBA, 0xBE])
    check sig != sig2
