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

const DefaultBudgetMs = 2000

type
  FuzzStats* = object
    target*: string
    iterations*: int
    crashes*: int
    accepts*: int      # raised a documented exception
    successes*: int    # decoded a sensible value
    elapsedMs*: float

proc randomBytes(r: var Rand; minLen, maxLen: int): seq[byte] =
  let n = r.rand(minLen .. maxLen)
  result = newSeq[byte](n)
  for i in 0 ..< n: result[i] = byte(r.rand(0 .. 255))

template fuzzLoop(name: string; budget: float; r: var Rand; body: untyped) =
  ## Run ``body`` repeatedly until ``budget`` ms elapse. ``r`` is in scope.
  ## ``body`` may declare ``data: seq[byte]`` for the current input.
  var s {.inject.} = FuzzStats(target: name)
  let t0 = epochTime()
  while (epochTime() - t0) * 1000.0 < budget:
    inc s.iterations
    let data {.inject.} = randomBytes(r, 0, 1024)
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
  echo "  ", name.align(30), " iters=", $s.iterations,
       "  succ=", $s.successes, "  accept=", $s.accepts,
       "  crash=", $s.crashes, "  (", $int(s.elapsedMs), " ms)"

# --- per-target fuzzers --------------------------------------------

proc fuzzPduHeader(r: var Rand; budgetMs: float) =
  fuzzLoop "rpc PduHeader", budgetMs, r:
    let buf = newBuffer(data)
    discard rpcPdu.readHeader(buf)

proc fuzzBindAck(r: var Rand; budgetMs: float) =
  fuzzLoop "rpc parseBindAckBody", budgetMs, r:
    let buf = newBuffer(data)
    if buf.remaining >= HeaderLen:
      discard rpcPdu.readHeader(buf)
      discard buf.parseBindAckBody()

proc fuzzRequest(r: var Rand; budgetMs: float) =
  fuzzLoop "rpc parseRequest", budgetMs, r:
    discard parseRequest(data)

proc fuzzNtlmNegotiate(r: var Rand; budgetMs: float) =
  fuzzLoop "ntlm parseNegotiate", budgetMs, r:
    discard parseNegotiate(data)

proc fuzzNtlmChallenge(r: var Rand; budgetMs: float) =
  fuzzLoop "ntlm parseChallenge", budgetMs, r:
    discard parseChallenge(data)

proc fuzzNtlmAuthenticate(r: var Rand; budgetMs: float) =
  fuzzLoop "ntlm parseAuthenticate", budgetMs, r:
    discard parseAuthenticate(data)

proc fuzzAvPairs(r: var Rand; budgetMs: float) =
  fuzzLoop "ntlm parseAvPairs", budgetMs, r:
    discard parseAvPairs(data)

proc fuzzDerOid(r: var Rand; budgetMs: float) =
  fuzzLoop "der parseOid", budgetMs, r:
    let b = newBuffer(data)
    discard derParseOid(b)

proc fuzzDerOctet(r: var Rand; budgetMs: float) =
  fuzzLoop "der parseOctetString", budgetMs, r:
    let b = newBuffer(data)
    discard derParseOctetString(b)

proc fuzzLdapMessage(r: var Rand; budgetMs: float) =
  fuzzLoop "ldap parseLdapMessage", budgetMs, r:
    discard ldapMessages.parseLdapMessage(data)

proc fuzzSmbHeader(r: var Rand; budgetMs: float) =
  fuzzLoop "smb2 readHeader", budgetMs, r:
    let b = newBuffer(data)
    discard smbHeader.readHeader(b)

# --- NDR scalar round-trip property test (not random-only) ---------

proc fuzzNdrU32RoundTrip(r: var Rand; budgetMs: float) =
  fuzzLoop "ndr u32 roundtrip", budgetMs, r:
    var v: uint32 = r.next().uint32
    let enc = ndrEncode[uint32](v)
    let dec = ndrDecode[uint32](enc)
    doAssert dec == v

proc fuzzNdrConformantArrayRoundTrip(r: var Rand; budgetMs: float) =
  fuzzLoop "ndr conformant array roundtrip", budgetMs, r:
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
    fuzzPduHeader, fuzzBindAck, fuzzRequest,
    fuzzNtlmNegotiate, fuzzNtlmChallenge, fuzzNtlmAuthenticate,
    fuzzAvPairs,
    fuzzDerOid, fuzzDerOctet,
    fuzzLdapMessage, fuzzSmbHeader,
    fuzzNdrU32RoundTrip, fuzzNdrConformantArrayRoundTrip]
  let per = budgetTotal / targets.len.float
  for f in targets: f(r, per)

  echo "(reproduce a crash by setting MSRPC_FUZZ_SEED to the seed above)"
