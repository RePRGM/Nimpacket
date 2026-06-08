## rpc/fragment.nim — splitting outbound stubs and reassembling
## fragmented inbound stubs.
##
## C706 §12.6.3.2: when a stub exceeds the negotiated max frag size, the
## sender splits it across multiple PDUs of the same type. The first
## fragment has PFC_FIRST_FRAG set, the last has PFC_LAST_FRAG, middle
## ones have neither. Each fragment's header carries the same call_id.
##
## We don't currently fragment auth verifiers — they always travel with
## the last fragment.

import ../common/buffers
import pdu, request

const
  ## Per-fragment header + body overhead for a REQUEST PDU without
  ## an object UUID: 16 (header) + 4 (alloc_hint) + 2 (p_cont_id) + 2 (opnum).
  RequestHeaderOverhead* = HeaderLen + 4 + 2 + 2

proc maxStubPerFragment*(maxFrag: int; hasObject: bool): int =
  ## Returns the largest stub-byte count that fits in a single PDU at
  ## the given negotiated max-fragment size.
  let extra = if hasObject: 16 else: 0
  result = maxFrag - RequestHeaderOverhead - extra

proc fragmentRequest*(r: RequestPdu; maxFrag: int): seq[seq[byte]] =
  ## Split ``r`` into one or more REQUEST PDUs of at most ``maxFrag``
  ## bytes each. Auth verifier is unsupported here (raises if present).
  if r.authVerifier.len != 0:
    raise newException(ValueError, "auth verifier fragmentation not supported")
  let chunk = maxStubPerFragment(maxFrag, r.hasObject)
  doAssert chunk > 0, "maxFrag too small for any payload"
  if r.stub.len <= chunk:
    return @[r.buildRequest()]

  result = @[]
  var off = 0
  var first = true
  while off < r.stub.len:
    let take = min(chunk, r.stub.len - off)
    let last = off + take == r.stub.len
    var flags: PfcFlags
    if first: flags.incl pfcFirstFrag
    if last:  flags.incl pfcLastFrag
    var sub = r
    sub.stub = r.stub[off ..< off + take]
    result.add sub.buildRequest(flags)
    off += take
    first = false

# --- response reassembly --------------------------------------------------

type
  Reassembler* = ref object
    callId*: uint32
    stub*: seq[byte]
    done*: bool
    error*: string

proc newReassembler*(callId: uint32): Reassembler =
  Reassembler(callId: callId)

proc feed*(r: Reassembler; pduBytes: openArray[byte]): bool =
  ## Consume one inbound RESPONSE PDU; returns true when the full
  ## response has been assembled. Fault PDUs set ``error`` and ``done``.
  let b = newBuffer(@pduBytes)
  let h = b.readHeader()
  if h.callId != r.callId:
    r.error = "callId mismatch in fragment: got " & $h.callId
    r.done = true
    return true
  case h.pType
  of ptResponse:
    let resp = parseResponse(@pduBytes)
    r.stub.add resp.stub
    if pfcLastFrag in h.flags:
      r.done = true
      return true
    return false
  of ptFault:
    let f = parseFault(@pduBytes)
    r.error = "fault 0x" & $f.status
    r.done = true
    return true
  else:
    r.error = "unexpected PDU type during reassembly: " & $h.pType
    r.done = true
    return true
