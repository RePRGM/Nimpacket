## tests/fuzz/fuzz_runner.nim — time-budgeted property fuzzer.
##
## Generates random byte buffers and feeds them to every protocol
## decoder we ship. The contract for each decoder under test:
##
##   1. Must not crash (no SIGSEGV / unhandled defects).
##   2. May raise a documented exception type (BufferRangeError,
##      DerError, ValueError, etc.) — that's an *accept* outcome.
##   3. Must produce output whose length-by-construction matches its
##      input (round-trip property, where applicable).
##
## Each fuzzer reports the failing seed on a crash so the failure
## is reproducible. Runtime is bounded by ``MSRPC_FUZZ_BUDGET_MS``
## (default 2000 ms total across all targets).

import std/[os, random, times, strutils]

import msrpc/common/buffers
import msrpc/ndr/[context, primitives, arrays, strings, pointers]
import msrpc/rpc/pdu as rpcPdu
import msrpc/rpc/[binds, request]
import msrpc/auth/ntlm/messages
import msrpc/auth/spnego/asn1
import msrpc/ldap/[ber, messages as ldapMessages]
import msrpc/smb/header as smbHeader
import msrpc/smb/smb3
import msrpc/auth/kerberos/[messages as krbMessages, asrep, tgsreq]
import generators

const DefaultBudgetMs = 2000

type
  FuzzStats* = object
    target*: string
    iterations*: int
    crashes*: int
    accepts*: int      # raised a documented exception
    successes*: int    # decoded a sensible value
    elapsedMs*: float

template fuzzLoop(name: string; budget: float; r: var Rand;
                  gen: untyped; body: untyped) =
  ## Run ``body`` repeatedly until ``budget`` ms elapse. ``data`` is the
  ## per-iteration byte buffer produced by ``gen`` (an expression).
  var s {.inject.} = FuzzStats(target: name)
  let t0 = epochTime()
  while (epochTime() - t0) * 1000.0 < budget:
    inc s.iterations
    let data {.inject.}: seq[byte] = gen
    try:
      body
      inc s.successes
    except CatchableError:
      inc s.accepts
    except Defect as d:
      inc s.crashes
      echo "  CRASH in ", name, " at iteration ", s.iterations,
           ": ", d.msg
      break
  s.elapsedMs = (epochTime() - t0) * 1000.0
  echo "  ", name.align(36), " iters=", $s.iterations,
       "  succ=", $s.successes, "  accept=", $s.accepts,
       "  crash=", $s.crashes, "  (", $int(s.elapsedMs), " ms)"

# --- per-target fuzzers --------------------------------------------

proc fuzzPduHeader(r: var Rand; budgetMs: float) =
  fuzzLoop "rpc PduHeader (random)", budgetMs, r, randomBytes(r, 0, 1024):
    let buf = newBuffer(data)
    discard rpcPdu.readHeader(buf)

proc fuzzPduHeaderStructured(r: var Rand; budgetMs: float) =
  fuzzLoop "rpc PduHeader (structured)", budgetMs, r, buildRpcPdu(r):
    let buf = newBuffer(data)
    discard rpcPdu.readHeader(buf)

proc fuzzBindAck(r: var Rand; budgetMs: float) =
  fuzzLoop "rpc parseBindAckBody", budgetMs, r, buildRpcPdu(r):
    let buf = newBuffer(data)
    if buf.remaining >= HeaderLen:
      discard rpcPdu.readHeader(buf)
      discard buf.parseBindAckBody()

proc fuzzRequest(r: var Rand; budgetMs: float) =
  fuzzLoop "rpc parseRequest", budgetMs, r, buildRpcPdu(r):
    discard parseRequest(data)

proc fuzzNtlmNegotiate(r: var Rand; budgetMs: float) =
  fuzzLoop "ntlm parseNegotiate", budgetMs, r, buildNtlmsspMessage(r):
    discard parseNegotiate(data)

proc fuzzNtlmChallenge(r: var Rand; budgetMs: float) =
  fuzzLoop "ntlm parseChallenge", budgetMs, r, buildNtlmsspMessage(r):
    discard parseChallenge(data)

proc fuzzNtlmAuthenticate(r: var Rand; budgetMs: float) =
  fuzzLoop "ntlm parseAuthenticate", budgetMs, r, buildNtlmsspMessage(r):
    discard parseAuthenticate(data)

proc fuzzAvPairs(r: var Rand; budgetMs: float) =
  fuzzLoop "ntlm parseAvPairs", budgetMs, r, randomBytes(r, 0, 1024):
    discard parseAvPairs(data)

proc fuzzDerOidStructured(r: var Rand; budgetMs: float) =
  fuzzLoop "der parseOid (structured)", budgetMs, r, buildDer(r):
    let b = newBuffer(data)
    discard derParseOid(b)

proc fuzzDerOctetStructured(r: var Rand; budgetMs: float) =
  fuzzLoop "der parseOctetString (structured)", budgetMs, r, buildDer(r):
    let b = newBuffer(data)
    discard derParseOctetString(b)

proc fuzzLdapMessage(r: var Rand; budgetMs: float) =
  fuzzLoop "ldap parseLdapMessage", budgetMs, r, buildLdapMessage(r):
    discard ldapMessages.parseLdapMessage(data)

proc fuzzSmbHeader(r: var Rand; budgetMs: float) =
  fuzzLoop "smb2 readHeader (structured)", budgetMs, r, buildSmb2Pdu(r):
    let b = newBuffer(data)
    discard smbHeader.readHeader(b)

proc fuzzSmb3Transform(r: var Rand; budgetMs: float) =
  ## Hit decryptPdu / readTransformHeader with random-but-shaped input.
  ## A failed AEAD check should return ok=false, not crash.
  fuzzLoop "smb3 decryptPdu", budgetMs, r,
           randomBytes(r, TransformHeaderLen, TransformHeaderLen + 256):
    var th = newSeq[byte](TransformHeaderLen)
    th[0] = 0xFD; th[1] = byte('S'); th[2] = byte('M'); th[3] = byte('B')
    for i in 4 ..< TransformHeaderLen: th[i] = data[i]
    let ct = data[TransformHeaderLen ..< data.len]
    var key = newSeq[byte](16)
    for i in 0 ..< 16: key[i] = byte(i + 1)
    discard decryptPdu(key, th, ct)

proc fuzzKrbError(r: var Rand; budgetMs: float) =
  fuzzLoop "krb parseKrbError", budgetMs, r, buildKrbMessage(r, 0x7E'u8):
    discard parseKrbError(data)

proc fuzzAsRep(r: var Rand; budgetMs: float) =
  fuzzLoop "krb parseAsRep", budgetMs, r, buildKrbMessage(r, 0x6B'u8):
    discard parseAsRep(data)

proc fuzzTgsRep(r: var Rand; budgetMs: float) =
  fuzzLoop "krb parseTgsRep", budgetMs, r, buildKrbMessage(r, 0x6D'u8):
    discard parseTgsRep(data)

proc fuzzEncKdcRepPart(r: var Rand; budgetMs: float) =
  fuzzLoop "krb parseEncKdcRepPart", budgetMs, r, buildKrbMessage(r, 0x79'u8):
    discard parseEncKdcRepPart(data)

# --- NDR scalar round-trip property test (not random-only) ---------

proc fuzzNdrU32RoundTrip(r: var Rand; budgetMs: float) =
  fuzzLoop "ndr u32 roundtrip", budgetMs, r, @[0'u8]:
    var v: uint32 = r.next().uint32
    let enc = ndrEncode[uint32](v)
    let dec = ndrDecode[uint32](enc)
    doAssert dec == v

proc fuzzNdrConformantArrayRoundTrip(r: var Rand; budgetMs: float) =
  fuzzLoop "ndr conformant array roundtrip", budgetMs, r, @[0'u8]:
    var v = newSeq[uint32](r.rand(0 .. 64))
    for i in 0 ..< v.len: v[i] = r.next().uint32
    let c = newNdrEncode(nsNdr)
    marshalConformantArray(c, v)
    let bytes = c.finish()
    let dc = newNdrDecode(bytes, nsNdr)
    var v2: seq[uint32]
    marshalConformantArray(dc, v2)
    doAssert v == v2

# --- entry point ---------------------------------------------------

when isMainModule:
  let envBudget = getEnv("MSRPC_FUZZ_BUDGET_MS")
  let budgetTotal =
    if envBudget.len > 0:
      try: parseInt(envBudget).float
      except ValueError: DefaultBudgetMs.float
    else: DefaultBudgetMs.float

  let seedEnv = getEnv("MSRPC_FUZZ_SEED")
  let seed =
    if seedEnv.len > 0:
      try: parseInt(seedEnv).int64
      except ValueError: (epochTime() * 1000.0).int64
    else: (epochTime() * 1000.0).int64
  echo "Fuzz seed: ", $seed, "   total budget: ", $int(budgetTotal), " ms"
  var r = initRand(seed)

  # Targets to fuzz, in declaration order. Budget is divided evenly.
  let targets = @[
    fuzzPduHeader, fuzzPduHeaderStructured,
    fuzzBindAck, fuzzRequest,
    fuzzNtlmNegotiate, fuzzNtlmChallenge, fuzzNtlmAuthenticate,
    fuzzAvPairs,
    fuzzDerOidStructured, fuzzDerOctetStructured,
    fuzzLdapMessage, fuzzSmbHeader, fuzzSmb3Transform,
    fuzzKrbError, fuzzAsRep, fuzzTgsRep, fuzzEncKdcRepPart,
    fuzzNdrU32RoundTrip, fuzzNdrConformantArrayRoundTrip]
  let per = budgetTotal / targets.len.float
  for f in targets: f(r, per)

  echo "(reproduce a crash by setting MSRPC_FUZZ_SEED to the seed above)"
