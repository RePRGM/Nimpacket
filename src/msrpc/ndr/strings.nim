## ndr/strings.nim — NDR conformant-varying UTF-16LE strings and
## MS-DTYP RPC_UNICODE_STRING (§2.3.10).
##
## A "wire" string here is the conformant-varying form:
##   max_count : u32/u64        (number of code units, includes NUL if any)
##   offset    : u32/u64        (always 0 in practice)
##   actual    : u32/u64        (code units actually present)
##   data      : [actual] u16   (UTF-16LE code units)
##
## RPC_UNICODE_STRING wraps the wire form with a Length/MaxLength header
## and a pointer to the array. We expose both because protocols use both.

import context, primitives, arrays
import ../common/[endian, unicode]

# --- bare conformant-varying wide string --------------------------------

proc marshalWideStringRaw*(c: NdrContext; s: var string;
                           nulTerminated = true) =
  ## In-place marshal of a UTF-16LE conformant-varying string.
  ##
  ## When ``nulTerminated`` is true (the MS-DTYP norm), the on-wire form
  ## includes a trailing U+0000. The Nim ``string`` value does not.
  var maxCount, offset, actual: uint64
  if c.dir == ndEncode:
    let units = toUtf16Units(s)
    let extra = if nulTerminated: 1 else: 0
    actual = uint64(units.len + extra)
    maxCount = actual
    offset = 0
  marshalCount(c, maxCount)
  marshalCount(c, offset)
  marshalCount(c, actual)
  case c.dir
  of ndEncode:
    let units = toUtf16Units(s)
    for u in units: c.buf.writeU16LE(u)
    if nulTerminated: c.buf.writeU16LE(0)
  of ndDecode:
    var units = newSeq[uint16](int(actual))
    for i in 0 ..< int(actual):
      units[i] = c.buf.readU16LE()
    if nulTerminated and units.len > 0 and units[^1] == 0'u16:
      units.setLen(units.len - 1)
    s = fromUtf16Units(units)

# --- MS-DTYP RPC_UNICODE_STRING ---------------------------------------

type
  RpcUnicodeString* = object
    ## Mirrors the MS-DTYP §2.3.10 struct.
    ##
    ## ``length`` and ``maxLength`` are byte counts (NOT code units),
    ## both including the terminating NUL if present.
    length*: uint16
    maxLength*: uint16
    value*: string                  ## UTF-8 (decoded from UTF-16LE)
    hasBuffer*: bool                ## true iff value pointer is non-null

proc rpcUnicodeString*(s: string; nulTerminated = true): RpcUnicodeString =
  ## Build a wire-ready RpcUnicodeString from a Nim string.
  let units = toUtf16Units(s).len + (if nulTerminated: 1 else: 0)
  result.length = uint16(units * 2)
  result.maxLength = result.length
  result.value = s
  result.hasBuffer = true

proc marshal*(c: NdrContext; v: var RpcUnicodeString) =
  ## Header (Length, MaxLength, pointer) then deferred buffer.
  marshal(c, v.length)
  marshal(c, v.maxLength)
  var refId: uint32 = 0
  if c.dir == ndEncode:
    refId = if v.hasBuffer: c.allocRefId() else: 0'u32
  marshal(c, refId)
  if c.dir == ndDecode:
    v.hasBuffer = refId != 0
  if not v.hasBuffer: return

  # The buffer is a conformant-varying wide-string array (without the
  # trailing NUL when Length == MaxLength and MaxLength counts the NUL).
  #
  # ``v`` is a ``var`` parameter and cannot be captured by closure; we
  # capture its address (a ``ptr``, which IS captureable) and access the
  # value through it. Safe as long as the caller drains ``c.deferred``
  # before the surrounding stack frame goes away — which the public
  # ``ndrEncode``/``ndrDecode`` wrappers guarantee.
  let vp: ptr RpcUnicodeString = addr v
  c.pushDeferred proc(c: NdrContext) =
    var maxCount, offset, actual: uint64
    let units = vp.maxLength.int div 2
    let actualUnits = vp.length.int div 2
    if c.dir == ndEncode:
      maxCount = uint64(units)
      offset = 0
      actual = uint64(actualUnits)
    marshalCount(c, maxCount)
    marshalCount(c, offset)
    marshalCount(c, actual)
    case c.dir
    of ndEncode:
      let u16 = toUtf16Units(vp.value)
      var emitted = 0
      for u in u16:
        if emitted >= int(actual): break
        c.buf.writeU16LE(u)
        inc emitted
      while emitted < int(actual):
        c.buf.writeU16LE(0)
        inc emitted
    of ndDecode:
      var u16 = newSeq[uint16](int(actual))
      for i in 0 ..< int(actual):
        u16[i] = c.buf.readU16LE()
      if u16.len > 0 and u16[^1] == 0'u16:
        u16.setLen(u16.len - 1)
      vp.value = fromUtf16Units(u16)
