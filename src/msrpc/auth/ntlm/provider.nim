## auth/ntlm/provider.nim — NTLM AuthProvider impl.
##
## Mediates between the abstract ``AuthProvider`` interface used by the
## RPC client and the lower-level NTLM messages/session machinery.
##
## Flow::
##
##   initialize(spn)  → NEGOTIATE_MESSAGE bytes
##   step(CHALLENGE)  → AUTHENTICATE_MESSAGE bytes; session keys derived
##   sign / seal      → delegated to NtlmSession

import std/times
import ../../crypto/[rand, rc4, hmac]
import ../../rpc/auth as rpcauth
import ntowf, messages, session

type
  NtlmRole* = enum
    nrClient
    nrServer

  NtlmProvider* = ref object of AuthProvider
    role*: NtlmRole
    anonymous*: bool
    domain*, user*, password*: string
    workstation*: string
    targetSpn*: string
    negotiateFlags*: NtlmFlags
    session*: NtlmSession
    serverChallenge*: array[8, byte]
    clientChallenge*: array[8, byte]
    targetInfo*: seq[byte]
    exportedSessionKey*: array[16, byte]
    encryptedRandomSessionKey*: array[16, byte]
    negotiateBytes*: seq[byte]    ## raw NEGOTIATE we sent (for MIC)
    challengeBytes*: seq[byte]    ## raw CHALLENGE we received (for MIC)

const DefaultNegotiateFlags*: NtlmFlags = {
  NEGOTIATE_UNICODE, NEGOTIATE_OEM, REQUEST_TARGET, NEGOTIATE_SIGN,
  NEGOTIATE_SEAL, NEGOTIATE_NTLM, NEGOTIATE_ALWAYS_SIGN,
  NEGOTIATE_EXTENDED_SESSIONSECURITY, NEGOTIATE_TARGET_INFO,
  NEGOTIATE_VERSION, NEGOTIATE_128, NEGOTIATE_KEY_EXCH, NEGOTIATE_56}

proc newNtlmProvider*(domain, user, password: string;
                      workstation = "WORKSTATION";
                      authLevel: AuthnLevel = alPktPrivacy;
                      role: NtlmRole = nrClient): NtlmProvider =
  result = NtlmProvider(
    role: role,
    anonymous: false,
    domain: domain, user: user, password: password,
    workstation: workstation,
    negotiateFlags: DefaultNegotiateFlags)
  result.state = asInit
  result.authType = atNtlm
  result.authLevel = authLevel
  result.maxSigSize = 16

proc newNtlmAnonymousProvider*(workstation = "WORKSTATION";
                                authLevel: AuthnLevel = alConnect;
                                role: NtlmRole = nrClient): NtlmProvider =
  ## Builds a provider that produces "null session" credentials per
  ## MS-NLMP §3.4.5.2.2: NEGOTIATE_ANONYMOUS set, no NT response,
  ## one-byte LM response, KeyExchangeKey = 16 zero bytes. Sign+seal
  ## still work but the session is unauthenticated, so most servers
  ## limit anonymous to a small whitelist of operations.
  result = NtlmProvider(
    role: role,
    anonymous: true,
    domain: "", user: "", password: "",
    workstation: workstation,
    negotiateFlags: DefaultNegotiateFlags + {NEGOTIATE_ANONYMOUS})
  result.state = asInit
  result.authType = atNtlm
  result.authLevel = authLevel
  result.maxSigSize = 16

# --- helpers ---------------------------------------------------------------

proc windowsFiletime(t: Time): uint64 =
  ## Convert POSIX time → 100-ns intervals since 1601-01-01 UTC.
  ## (Windows EPOCH is 11644473600 seconds before 1970-01-01.)
  let epochSecs = uint64(t.toUnix()) + 11644473600'u64
  result = epochSecs * 10_000_000'u64

# --- AuthProvider methods -------------------------------------------------

method initialize*(p: NtlmProvider; targetSpn: string): seq[byte] =
  p.targetSpn = targetSpn
  let m = NegotiateMessage(
    flags: p.negotiateFlags,
    domain: "", workstation: "",
    hasVersion: true,
    version: DefaultVersion)
  result = m.build()
  p.negotiateBytes = result
  p.state = asContinue

method step*(p: NtlmProvider; serverToken: openArray[byte]): seq[byte] =
  p.challengeBytes = @serverToken
  let cm = parseChallenge(serverToken)
  p.serverChallenge = cm.serverChallenge
  p.targetInfo = cm.targetInfo
  # Intersect server-offered flags with our requested flags, but keep
  # ANONYMOUS if we asked for it (some servers strip it from CHALLENGE).
  let wantAnon = NEGOTIATE_ANONYMOUS in p.negotiateFlags
  p.negotiateFlags = p.negotiateFlags * cm.flags
  if wantAnon: p.negotiateFlags.incl NEGOTIATE_ANONYMOUS

  # --- anonymous fast path ---
  #
  # Wire layout matches what impacket emits (and Samba accepts):
  #   - No NEGOTIATE_VERSION (so no Version block in the message).
  #   - NEGOTIATE_ANONYMOUS *not* set in the AUTHENTICATE flags — the
  #     server detects anonymous-ness from the empty NT response, the
  #     single-byte LM response, and the empty username/domain fields.
  #   - LM response = single zero byte.
  #   - NT response = empty.
  #   - KeyExchangeKey = 16 zero bytes (per MS-NLMP §3.4.5.1).
  #   - We generate a random ExportedSessionKey and ship it as
  #     RC4(KeyExchangeKey=zeros, ExportedSessionKey) in the
  #     EncryptedRandomSessionKey field; the server recovers it with
  #     the same zero-keyed RC4 stream.
  if p.anonymous:
    var anonFlags = p.negotiateFlags
    anonFlags.excl NEGOTIATE_ANONYMOUS
    anonFlags.excl NEGOTIATE_VERSION

    let rsk = randomBytes(16)
    for i in 0 ..< 16: p.exportedSessionKey[i] = rsk[i]
    var zeros: array[16, byte]
    let enc = rc4(zeros, p.exportedSessionKey)
    for i in 0 ..< 16: p.encryptedRandomSessionKey[i] = enc[i]

    var am = AuthenticateMessage(
      flags: anonFlags,
      lmResponse: @[0'u8],
      ntResponse: @[],
      domain: "", user: "", workstation: "",
      encryptedRandomSessionKey: @(p.encryptedRandomSessionKey),
      hasVersion: false)

    result = am.build()
    p.session = newNtlmSession(p.exportedSessionKey)
    p.state = asEstablished
    return

  # Client challenge (8 random bytes).
  let cc = randomBytes(8)
  for i in 0 ..< 8: p.clientChallenge[i] = cc[i]

  let responseKey = ntowfV2(p.password, p.user, p.domain)

  # Per MS-NLMP §3.1.5.1.2: if the server's CHALLENGE TargetInfo carries
  # an MsvAvTimestamp pair, the client MUST echo that exact value in
  # the NTLMv2 response. Otherwise use the current system time.
  var ts = windowsFiletime(getTime())
  let avPairs = parseAvPairs(cm.targetInfo)
  var hasServerTimestamp = false
  for pair in avPairs:
    if pair.id == MsvAvTimestamp and pair.value.len == 8:
      ts = 0
      for i in 0 ..< 8:
        ts = ts or (uint64(pair.value[i]) shl (i * 8))
      hasServerTimestamp = true
      break

  # MIC handling (MS-NLMP §3.1.5.1.2):
  # When the server CHALLENGE carries MsvAvTimestamp, the client SHOULD
  # produce a MIC for downgrade protection. To signal that we did, we
  # add (or set) MsvAvFlags with bit 0x2 in the AV_PAIRs that go into
  # the NTLMv2 response's "temp" blob.

  var targetInfoForResponse = p.targetInfo
  if hasServerTimestamp:
    # Rebuild AV_PAIR list with MsvAvFlags set to (existing | 0x2).
    var rebuilt: seq[AvPair] = @[]
    var sawFlags = false
    for pair in avPairs:
      if pair.id == MsvAvFlags and pair.value.len == 4:
        var v = uint32(pair.value[0]) or
                (uint32(pair.value[1]) shl 8) or
                (uint32(pair.value[2]) shl 16) or
                (uint32(pair.value[3]) shl 24)
        v = v or 0x00000002'u32
        rebuilt.add AvPair(id: MsvAvFlags, value: @[
          byte(v and 0xff'u32), byte((v shr 8) and 0xff'u32),
          byte((v shr 16) and 0xff'u32), byte((v shr 24) and 0xff'u32)])
        sawFlags = true
      else:
        rebuilt.add pair
    if not sawFlags:
      rebuilt.add AvPair(id: MsvAvFlags,
                          value: @[0x02'u8, 0, 0, 0])
    targetInfoForResponse = serialize(rebuilt)

  let ntv2 = computeNtV2Response(responseKey,
                                 p.serverChallenge, p.clientChallenge,
                                 ts, targetInfoForResponse)

  # KeyExchangeKey = SessionBaseKey in NTLMv2.
  # Either generate a random ExportedSessionKey (if KEY_EXCH) or use
  # KeyExchangeKey directly.
  if NEGOTIATE_KEY_EXCH in p.negotiateFlags:
    let rsk = randomBytes(16)
    for i in 0 ..< 16: p.exportedSessionKey[i] = rsk[i]
    let enc = rc4(ntv2.sessionBaseKey, p.exportedSessionKey)
    for i in 0 ..< 16: p.encryptedRandomSessionKey[i] = enc[i]
  else:
    p.exportedSessionKey = ntv2.sessionBaseKey

  # Build AUTHENTICATE. ``hasVersion`` mirrors the NEGOTIATE_VERSION
  # flag (parser conditions on the flag, not on the build-time bool);
  # otherwise the parser would misread the MIC slot.
  let useVersion = NEGOTIATE_VERSION in p.negotiateFlags
  var am = AuthenticateMessage(
    flags: p.negotiateFlags,
    lmResponse: @[],     # LMv2 response not strictly needed when timestamp
                         # is present in NTLMv2 response (MS-NLMP §3.1.5.1.2)
    ntResponse: ntv2.response,
    domain: p.domain,
    user: p.user,
    workstation: p.workstation,
    hasVersion: useVersion,
    version: DefaultVersion,
    hasMic: hasServerTimestamp)
  if NEGOTIATE_KEY_EXCH in p.negotiateFlags:
    am.encryptedRandomSessionKey = newSeq[byte](16)
    for i in 0 ..< 16:
      am.encryptedRandomSessionKey[i] = p.encryptedRandomSessionKey[i]

  result = am.build()
  p.session = newNtlmSession(p.exportedSessionKey)

  if hasServerTimestamp:
    # MIC sits right after sig(8) + type(4) + 6*Fields(48) + flags(4)
    # plus optional Version(8). When version is absent, MIC starts at 64.
    let micOffset = if useVersion: 72 else: 64
    # Compute MIC over the concatenation, with the MIC slot zeroed
    # (which is already its current state in ``result``).
    var msg = newSeq[byte](p.negotiateBytes.len + p.challengeBytes.len +
                            result.len)
    var off = 0
    for b in p.negotiateBytes: msg[off] = b; inc off
    for b in p.challengeBytes: msg[off] = b; inc off
    for b in result:          msg[off] = b; inc off
    let mic = hmacMd5(p.exportedSessionKey, msg)
    for i in 0 ..< 16: result[micOffset + i] = mic[i]
  p.state = asEstablished

method sign*(p: NtlmProvider; pdu: openArray[byte]): seq[byte] =
  ## Signed-only (no encryption) — returns 16-byte verifier.
  let sig = p.session.signOutgoing(pdu, doSeal = false)
  result = newSeq[byte](16)
  for i in 0 ..< 16: result[i] = sig[i]

method seal*(p: NtlmProvider; pdu: var openArray[byte]): seq[byte] =
  ## Sealed: ``pdu`` is fully RC4'd in place. Caller passes ONLY the
  ## bytes that should be sealed (stub + pad), not the sec_trailer.
  let sig = p.session.sealOutgoing(pdu)
  result = newSeq[byte](16)
  for i in 0 ..< 16: result[i] = sig[i]

method verify*(p: NtlmProvider; pdu: openArray[byte];
               verifier: openArray[byte]): bool =
  p.session.verifyIncoming(pdu, verifier)

method unseal*(p: NtlmProvider; pdu: var openArray[byte];
               verifier: openArray[byte]): bool =
  p.session.unsealIncoming(pdu, verifier)

# --- RPC-flavoured wrappers used by rpc/client.nim ----------------------

proc rpcSignSeal*(p: NtlmProvider; data: var openArray[byte];
                  sealLen: int): seq[byte] =
  ## Sign+seal an outbound RPC payload. The session's key-direction
  ## selection follows the provider's ``role``: a client provider uses
  ## the client-to-server sign/seal keys, a server provider uses the
  ## server-to-client keys.
  let sig = p.session.signSealPartial(data, sealLen,
                                       forClient = (p.role == nrClient))
  result = newSeq[byte](16)
  for i in 0 ..< 16: result[i] = sig[i]

proc rpcUnsealVerify*(p: NtlmProvider; data: var openArray[byte];
                      sealLen: int; verifier: openArray[byte]): bool =
  ## Inverse: a client unseals server→client traffic, a server unseals
  ## client→server traffic.
  p.session.unsealVerifyPartial(data, sealLen, verifier,
                                 forClient = (p.role == nrServer))
