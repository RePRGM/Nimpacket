## ndr/primitives.nim — bool, scalars, fixed-size types.
##
## Every ``marshal`` proc is bidirectional: it inspects ``c.dir`` and
## either reads from or writes to ``c.buf``. NDR alignment for each
## scalar matches C706 §14.

import context
import ../common/[buffers, endian]

# --- helpers --------------------------------------------------------------

template alignAndDo(c: NdrContext; n: int; body: untyped) =
  c.align(n)
  body

# --- bool / byte ---------------------------------------------------------

proc marshal*(c: NdrContext; v: var bool) =
  case c.dir
  of ndEncode: c.buf.writeByte(if v: 1'u8 else: 0'u8)
  of ndDecode: v = c.buf.readByte() != 0

proc marshal*(c: NdrContext; v: var uint8) =
  case c.dir
  of ndEncode: c.buf.writeByte(v)
  of ndDecode: v = c.buf.readByte()

proc marshal*(c: NdrContext; v: var int8) =
  case c.dir
  of ndEncode: c.buf.writeByte(cast[uint8](v))
  of ndDecode: v = cast[int8](c.buf.readByte())

# --- 16-bit -------------------------------------------------------------

proc marshal*(c: NdrContext; v: var uint16) =
  c.align(2)
  case c.dir
  of ndEncode: c.buf.writeU16LE(v)
  of ndDecode: v = c.buf.readU16LE()

proc marshal*(c: NdrContext; v: var int16) =
  c.align(2)
  case c.dir
  of ndEncode: c.buf.writeI16LE(v)
  of ndDecode: v = c.buf.readI16LE()

# --- 32-bit -------------------------------------------------------------

proc marshal*(c: NdrContext; v: var uint32) =
  c.align(4)
  case c.dir
  of ndEncode: c.buf.writeU32LE(v)
  of ndDecode: v = c.buf.readU32LE()

proc marshal*(c: NdrContext; v: var int32) =
  c.align(4)
  case c.dir
  of ndEncode: c.buf.writeI32LE(v)
  of ndDecode: v = c.buf.readI32LE()

# --- 64-bit (hyper) ----------------------------------------------------

proc marshal*(c: NdrContext; v: var uint64) =
  ## NDR and NDR64 both align ``hyper`` to 8 bytes.
  c.align(8)
  case c.dir
  of ndEncode: c.buf.writeU64LE(v)
  of ndDecode: v = c.buf.readU64LE()

proc marshal*(c: NdrContext; v: var int64) =
  c.align(8)
  case c.dir
  of ndEncode: c.buf.writeI64LE(v)
  of ndDecode: v = c.buf.readI64LE()

# --- enum (16-bit, C706 §14.2.5) ---------------------------------------

proc marshalEnum16*[E: enum](c: NdrContext; v: var E) =
  c.align(2)
  case c.dir
  of ndEncode: c.buf.writeU16LE(uint16(ord(v)))
  of ndDecode: v = E(c.buf.readU16LE())

# --- raw fixed-size byte blob ------------------------------------------

proc marshalFixedBytes*(c: NdrContext; arr: var openArray[byte]) =
  ## Fixed-length octet array; no alignment, no length prefix.
  case c.dir
  of ndEncode:
    c.buf.writeBytes(arr)
  of ndDecode:
    let data = c.buf.readBytes(arr.len)
    for i in 0 ..< arr.len:
      arr[i] = data[i]

# --- convenience top-level wrappers ------------------------------------

proc ndrEncode*[T](v: T; syntax = nsNdr): seq[byte] =
  mixin marshal
  let c = newNdrEncode(syntax)
  var local = v
  marshal(c, local)
  c.drainDeferred()
  result = c.finish()

proc ndrDecode*[T](data: openArray[byte]; syntax = nsNdr): T =
  mixin marshal
  let c = newNdrDecode(data, syntax)
  marshal(c, result)
  c.drainDeferred()
