## ndr/pointers.nim — NDR pointer marshalling (C706 §14.3.10).
##
## NDR has four pointer flavours:
##
##  * unique  — non-null distinct, may be NULL; the only one we need most often
##  * ref     — guaranteed non-null, no referent id on the wire? actually yes,
##              embedded ref pointers DO have a referent id (just non-null)
##  * full    — supports aliasing; same value yields same referent id
##  * ptr     — alias for "unique" in many MIDL configurations
##
## The referent id is a u32 in NDR3 and a u64 in NDR64, with matching
## alignment. Top-level pointers (immediate argument) have NO referent
## id; only embedded pointers do. Helpers below cover both forms.
##
## Pointer *referent data* is normally marshalled inline for top-level
## ref pointers, and deferred for embedded pointers in structs. Callers
## may either inline ``marshalReferent`` immediately or push it onto
## the deferred queue with ``defer``.

import context
import ../common/endian

type
  PtrKind* = enum
    pkRef     ## non-null, referent id always non-zero
    pkUnique  ## may be null
    pkFull    ## aliasing — same value reuses the same referent id
    pkPtr     ## synonym for unique in most MIDLs

# --- referent id width --------------------------------------------------

proc marshalRefId*(c: NdrContext; id: var uint64) =
  case c.syntax
  of nsNdr:
    c.align(4)
    var tmp = uint32(id)
    case c.dir
    of ndEncode: c.buf.writeU32LE(tmp)
    of ndDecode: tmp = c.buf.readU32LE(); id = uint64(tmp)
  of nsNdr64:
    c.align(8)
    case c.dir
    of ndEncode: c.buf.writeU64LE(id)
    of ndDecode: id = c.buf.readU64LE()

# --- top-level pointer (no referent id on wire) ------------------------

proc marshalTopRefPointer*[T](c: NdrContext; p: var ref T) =
  ## Top-level ref pointer; the referent is marshalled inline and the
  ## pointer's presence is implicit (no id).
  mixin marshal
  if c.dir == ndDecode and p == nil:
    new p
  if p == nil:
    raise newException(NdrError, "top-level ref pointer is nil")
  marshal(c, p[])

proc marshalTopUniquePointer*[T](c: NdrContext; p: var ref T) =
  ## Top-level unique pointer: u32/u64 referent id followed by inline data.
  mixin marshal
  var refId: uint64 = 0
  if c.dir == ndEncode and p != nil:
    refId = uint64(c.allocRefId())
  marshalRefId(c, refId)
  if c.dir == ndDecode:
    if refId == 0:
      p = nil
    else:
      new p
  if p != nil:
    marshal(c, p[])

# --- embedded pointers (referent id, referent data is deferred) --------

proc marshalEmbeddedUniquePointer*[T](c: NdrContext; p: var ref T) =
  mixin marshal
  var refId: uint64 = 0
  if c.dir == ndEncode and p != nil:
    refId = uint64(c.allocRefId())
  marshalRefId(c, refId)
  if c.dir == ndDecode:
    if refId == 0:
      p = nil
    else:
      new p
  if p != nil:
    let captured = p
    c.pushDeferred proc(c: NdrContext) =
      mixin marshal
      marshal(c, captured[])

proc marshalEmbeddedRefPointer*[T](c: NdrContext; p: var ref T) =
  ## Embedded ref pointer: id is non-zero but unused for branching.
  mixin marshal
  var refId: uint64 = 0
  if c.dir == ndEncode:
    if p == nil:
      raise newException(NdrError, "embedded ref pointer is nil")
    refId = uint64(c.allocRefId())
  marshalRefId(c, refId)
  if c.dir == ndDecode:
    new p
  let captured = p
  c.pushDeferred proc(c: NdrContext) =
    mixin marshal
    marshal(c, captured[])
