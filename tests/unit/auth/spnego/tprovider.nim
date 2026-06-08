import std/unittest
import msrpc/auth/ntlm/[messages, provider]
import msrpc/auth/spnego/[asn1, provider]
import msrpc/rpc/auth as rpcauth

suite "spnego provider":
  test "initial token wraps NTLM Type-1 in GSS-API+SPNEGO":
    let inner = newNtlmProvider("D", "u", "p")
    let sp = newSpnegoProvider(inner)
    let token = sp.initialize("cifs/host")
    # Should start with [APPLICATION 0] tag = 0x60.
    check token[0] == 0x60'u8
    # SPNEGO OID embedded.
    let spnegoOid = derEncodeOid(@SpnegoOidArcs)
    var foundOid = false
    for i in 0 .. token.len - spnegoOid.len:
      if token[i ..< i + spnegoOid.len] == spnegoOid:
        foundOid = true; break
    check foundOid

  test "unwrap a server SPNEGO response":
    # Build a fake server SPNEGO response containing an NTLM CHALLENGE.
    let ntlmType2 = ChallengeMessage(
      flags: {NEGOTIATE_UNICODE, NEGOTIATE_NTLM},
      serverChallenge: [0x11'u8, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88],
      hasVersion: false).build()

    # Wrap as bare NegTokenResp { [2] responseToken = ntlmType2 }.
    let respToken = derTLV(ctxConstructed(2),
                            derTLV(tagOctetString, ntlmType2))
    let respBody = derTLV(tagSequence, respToken)
    let wrapped = derTLV(ctxConstructed(1), respBody)

    let recovered = unwrapChallengeToken(wrapped)
    check recovered == ntlmType2

  test "step round-trip: initialize → step yields SPNEGO-wrapped Type-3":
    let inner = newNtlmProvider("Domain", "user", "Password")
    let sp = newSpnegoProvider(inner)
    discard sp.initialize("cifs/srv")

    # Server replies with a SPNEGO-wrapped NTLM CHALLENGE.
    let ntlmType2 = ChallengeMessage(
      flags: {NEGOTIATE_UNICODE, NEGOTIATE_NTLM,
              NEGOTIATE_EXTENDED_SESSIONSECURITY, NEGOTIATE_TARGET_INFO,
              NEGOTIATE_KEY_EXCH, NEGOTIATE_128},
      serverChallenge: [0xAA'u8, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22],
      targetInfo: @[],
      hasVersion: false).build()
    let serverResp = derTLV(ctxConstructed(1),
                             derTLV(tagSequence,
                               derTLV(ctxConstructed(2),
                                 derTLV(tagOctetString, ntlmType2))))

    let clientToken = sp.step(serverResp)
    # Should be a NegTokenResp ([1] tag = 0xA1).
    check clientToken[0] == 0xA1'u8
    # Should contain a parseable AUTHENTICATE inside.
    # Easiest check: unwrap as NegTokenResp would and parse.
    let innerType3 = unwrapChallengeToken(clientToken)
    let am = parseAuthenticate(innerType3)
    check am.user == "user"
    check am.domain == "Domain"
    check am.ntResponse.len >= 16
