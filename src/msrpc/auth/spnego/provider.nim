## auth/spnego/provider.nim — SPNEGO AuthProvider that wraps any
## underlying mechanism provider (today: NTLM).
##
## On the wire (RFC 4178 + MS-SPNG):
##
##   First client → server token:
##     [APPLICATION 0] {            -- GSS-API InitialContextToken
##       OID SPNEGO (1.3.6.1.5.5.2)
##       [0] NegTokenInit {
##         [0] MechTypeList         -- [NTLMSSP OID]
##         [2] mechToken            -- NTLM Type-1
##       }
##     }
##
##   Subsequent tokens (no GSS-API wrapper):
##     [1] NegTokenResp {
##       [0] negState (optional)
##       [1] supportedMech (optional)
##       [2] responseToken         -- NTLM Type-2 or Type-3
##       [3] mechListMIC (optional)
##     }

import ../../common/buffers
import ../../rpc/auth as rpcauth
import ../ntlm/provider as ntlm_provider
import ../kerberos/provider as krb_provider
import asn1

type
  SpnegoMech* = enum
    smNtlm
    smKerberos

  SpnegoProvider* = ref object of AuthProvider
    inner*: AuthProvider              ## underlying mechanism (NTLM or Kerberos)
    mech*: SpnegoMech
    sentFirstToken*: bool

proc newSpnegoProvider*(inner: NtlmProvider): SpnegoProvider =
  result = SpnegoProvider(inner: inner, mech: smNtlm, sentFirstToken: false)
  result.state = inner.state
  result.authType = atGssNegotiate    # 9 = SPNEGO
  result.authLevel = inner.authLevel
  result.maxSigSize = inner.maxSigSize

proc newSpnegoKerberos*(inner: AuthProvider): SpnegoProvider =
  ## Wrap a Kerberos provider for SPNEGO. The inner is typed as
  ## AuthProvider to avoid an import cycle with the kerberos module.
  result = SpnegoProvider(inner: inner, mech: smKerberos, sentFirstToken: false)
  result.state = inner.state
  result.authType = atGssNegotiate
  result.authLevel = inner.authLevel
  result.maxSigSize = inner.maxSigSize

# --- helpers ---------------------------------------------------------

proc wrapInitialToken(innerTok: openArray[byte]; mech: SpnegoMech): seq[byte] =
  ## GSS-API + SPNEGO NegTokenInit wrap of an inner mech token.
  ## For Kerberos, innerTok is the GSS-API wrapped AP-REQ (its outer
  ## [APP 0] tag stays in place; SPNEGO just transports the bytes).
  let mechOid =
    case mech
    of smNtlm: derEncodeOid(@NtlmsspOidArcs)
    of smKerberos: derEncodeOid(@KerberosOidArcs)
  # MechTypeList = SEQUENCE OF MechType
  let mechList = derTLV(tagSequence, mechOid)
  # [0] mechTypes
  let mechTypesTagged = derTLV(ctxConstructed(0), mechList)
  # [2] mechToken
  let mechTokenTagged = derTLV(ctxConstructed(2),
                                derTLV(tagOctetString, innerTok))
  # NegTokenInit body = SEQUENCE { mechTypes, mechToken }
  let initBody = newBuffer()
  initBody.writeBytes(mechTypesTagged)
  initBody.writeBytes(mechTokenTagged)
  let negTokenInit = derTLV(tagSequence, initBody.consumed)
  # [0] negTokenInit choice
  let negTokenChoice = derTLV(ctxConstructed(0), negTokenInit)
  # Outer: [APPLICATION 0] { SPNEGO OID, choice }
  let outer = newBuffer()
  outer.writeBytes(derEncodeOid(@SpnegoOidArcs))
  outer.writeBytes(negTokenChoice)
  result = derTLV(appConstructed(0), outer.consumed)

proc wrapResponseToken(innerNtlm: openArray[byte]): seq[byte] =
  ## Bare NegTokenResp (no GSS-API wrapper) carrying NTLM Type-3.
  let respTokenTagged = derTLV(ctxConstructed(2),
                                derTLV(tagOctetString, innerNtlm))
  let respBody = derTLV(tagSequence, respTokenTagged)
  result = derTLV(ctxConstructed(1), respBody)

proc unwrapChallengeToken*(spnegoBytes: openArray[byte]): seq[byte] =
  ## Extract the inner mech token (NTLM Type-2 CHALLENGE) from a
  ## server SPNEGO response. Accepts both bare NegTokenResp and the
  ## GSS-API-wrapped form some servers send for compatibility.
  let b = newBuffer(@spnegoBytes)
  var tag = b.peekByte()
  if tag == appConstructed(0):
    # GSS-API outer wrap — unwrap to get the negTokenResp/Init inside.
    discard b.derReadTag(appConstructed(0))
    # The inner data is `OID SpnegoOID || NegotiationToken`. Skip the OID.
    discard derParseOid(b)
    tag = b.peekByte()
  if tag == ctxConstructed(1):
    # NegTokenResp
    discard b.derReadTag(ctxConstructed(1))
    discard b.derReadTag(tagSequence)
    while b.remaining > 0:
      let t = b.peekByte()
      let plen = b.derReadTag(t)
      let pend = b.pos + plen
      case t
      of ctxConstructed(2):
        # responseToken — OCTET STRING with the mech bytes
        return derParseOctetString(b)
      else:
        b.seek(pend)
  elif tag == ctxConstructed(0):
    # Server occasionally responds with NegTokenInit (rare)
    discard b.derReadTag(ctxConstructed(0))
    discard b.derReadTag(tagSequence)
    while b.remaining > 0:
      let t = b.peekByte()
      let plen = b.derReadTag(t)
      let pend = b.pos + plen
      case t
      of ctxConstructed(2): return derParseOctetString(b)
      else: b.seek(pend)
  raise newException(DerError, "no mechToken found in SPNEGO response")

# --- AuthProvider implementation ------------------------------------

method initialize*(p: SpnegoProvider; targetSpn: string): seq[byte] =
  let inner = p.inner.initialize(targetSpn)
  p.state = p.inner.state
  p.sentFirstToken = true
  result = wrapInitialToken(inner, p.mech)

method step*(p: SpnegoProvider; serverToken: openArray[byte]): seq[byte] =
  let challenge = unwrapChallengeToken(serverToken)
  let response = p.inner.step(challenge)
  p.state = p.inner.state
  # Kerberos returns empty after AP-REQ (no follow-up token); only wrap
  # if there's actually something to send.
  if response.len == 0:
    result = @[]
  else:
    result = wrapResponseToken(response)

# Sign/seal/verify/unseal pass through to the inner provider — SPNEGO
# only affects the token exchange, not per-message protection.
method sign*(p: SpnegoProvider; pdu: openArray[byte]): seq[byte] =
  p.inner.sign(pdu)

method seal*(p: SpnegoProvider; pdu: var openArray[byte]): seq[byte] =
  p.inner.seal(pdu)

method verify*(p: SpnegoProvider; pdu: openArray[byte];
               verifier: openArray[byte]): bool =
  p.inner.verify(pdu, verifier)

method unseal*(p: SpnegoProvider; pdu: var openArray[byte];
               verifier: openArray[byte]): bool =
  p.inner.unseal(pdu, verifier)

method rpcSignSeal*(p: SpnegoProvider; data: var openArray[byte];
                    sealLen: int): seq[byte] =
  ## Per-message sign+seal.
  ##  - NTLM: RC4 seal data[0..sealLen-1] in place, return 16-byte sig.
  ##  - Kerberos at alPktIntegrity: compute an RFC 4121 MIC over the
  ##    same byte range; data stays in cleartext, verifier carries
  ##    the MIC token (TokenHeader(16) || HMAC(12) = 28 bytes).
  ##  - Kerberos at alPktPrivacy: would require the MS-RPCE WrapEx
  ##    layout (cleartext header offset + EC + RRC fields) that hasn't
  ##    been validated against a real Microsoft target. Use
  ##    ``krbWrapData`` on the inner KerberosProvider for GSS Wrap
  ##    directly without the RPC framing in the meantime.
  case p.mech
  of smNtlm:
    result = NtlmProvider(p.inner).rpcSignSeal(data, sealLen)
  of smKerberos:
    let krb = KerberosProvider(p.inner)
    case p.authLevel
    of alPktIntegrity:
      result = krbGetMic(krb, data.toOpenArray(0, sealLen - 1))
    of alPktPrivacy:
      result = krbWrapExSeal(krb, data, sealLen)
    else:
      result = @[]

method rpcUnsealVerify*(p: SpnegoProvider; data: var openArray[byte];
                        sealLen: int; verifier: openArray[byte]): bool =
  case p.mech
  of smNtlm:
    result = NtlmProvider(p.inner).rpcUnsealVerify(data, sealLen, verifier)
  of smKerberos:
    let krb = KerberosProvider(p.inner)
    case p.authLevel
    of alPktIntegrity:
      result = krbVerifyMic(krb, data.toOpenArray(0, sealLen - 1), verifier)
    of alPktPrivacy:
      result = krbWrapExUnseal(krb, data, sealLen, verifier)
    else:
      result = true
