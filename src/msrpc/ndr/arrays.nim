## ndr/arrays.nim — NDR array variants (C706 §14.3.3).
##
##  * fixed                — known size, no header
##  * conformant           — leading max_count
##  * varying              — leading offset + actual_count, header *follows* size hints
##  * conformant-varying   — leading max_count, then offset + actual_count
##
## NDR64 widens all of those counts from u32 to u64 and uses 8-byte
## alignment for them. The element type's own ``marshal`` is invoked
## for each element.

import context, primitives
import ../common/[buffers, endian]

# --- count helpers -------------------------------------------------------

proc marshalCount*(c: NdrContext; v: var uint64) =
  ## NDR3 → u32, NDR64 → u64.
  case c.syntax
  of nsNdr:
    c.align(4)
    var tmp = uint32(v)
    case c.dir
    of ndEncode: c.buf.writeU32LE(tmp)
    of ndDecode: tmp = c.buf.readU32LE(); v = uint64(tmp)
  of nsNdr64:
    c.align(8)
    case c.dir
    of ndEncode: c.buf.writeU64LE(v)
    of ndDecode: v = c.buf.readU64LE()

# --- fixed array --------------------------------------------------------

proc marshalFixedArray*[T](c: NdrContext; arr: var openArray[T]) =
  for i in 0 ..< arr.len:
    marshal(c, arr[i])

# --- conformant array ---------------------------------------------------

proc marshalConformantArray*[T](c: NdrContext; arr: var seq[T]) =
  var n: uint64 = uint64(arr.len)
  marshalCount(c, n)
  if c.dir == ndDecode:
    arr.setLen(int(n))
  for i in 0 ..< int(n):
    marshal(c, arr[i])

# --- varying array ------------------------------------------------------

proc marshalVaryingArray*[T](c: NdrContext; arr: var seq[T];
                             offset: var uint64; actualCount: var uint64) =
  marshalCount(c, offset)
  marshalCount(c, actualCount)
  if c.dir == ndDecode:
    arr.setLen(int(actualCount))
  for i in 0 ..< int(actualCount):
    marshal(c, arr[i])

# --- conformant-varying array ------------------------------------------

proc marshalConformantVaryingArray*[T](c: NdrContext; arr: var seq[T];
                                       maxCount: var uint64;
                                       offset: var uint64;
                                       actualCount: var uint64) =
  marshalCount(c, maxCount)
  marshalCount(c, offset)
  marshalCount(c, actualCount)
  if c.dir == ndDecode:
    arr.setLen(int(actualCount))
  for i in 0 ..< int(actualCount):
    marshal(c, arr[i])
