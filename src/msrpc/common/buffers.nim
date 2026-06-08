## buffers.nim — byte buffer with read/write cursor.
##
## Used by every layer above (endian helpers, NDR, RPC PDU framing).
## A single ``Buffer`` is both a writer and a reader; ``pos`` is the
## cursor and ``data`` grows on write.

import std/strutils

type
  Buffer* = ref object
    data*: seq[byte]
    pos*: int

  BufferRangeError* = object of CatchableError

proc newBuffer*(cap = 0): Buffer =
  ## Empty buffer; ``cap`` is a hint for the underlying seq.
  result = Buffer(data: newSeqOfCap[byte](cap), pos: 0)

proc newBuffer*(data: openArray[byte]): Buffer =
  ## Wrap a copy of ``data`` and place the cursor at the start.
  result = Buffer(data: @data, pos: 0)

proc len*(b: Buffer): int {.inline.} = b.data.len
proc remaining*(b: Buffer): int {.inline.} = b.data.len - b.pos
proc atEnd*(b: Buffer): bool {.inline.} = b.pos >= b.data.len

proc seek*(b: Buffer; pos: int) =
  if pos < 0 or pos > b.data.len:
    raise newException(BufferRangeError, "seek out of range: " & $pos)
  b.pos = pos

proc skip*(b: Buffer; n: int) =
  if n < 0 or b.pos + n > b.data.len:
    raise newException(BufferRangeError, "skip out of range: " & $n)
  b.pos += n

proc reserve*(b: Buffer; extra: int) =
  ## Ensure ``b.data`` has room for ``extra`` additional bytes past ``pos``.
  let need = b.pos + extra
  if need > b.data.len:
    b.data.setLen(need)

proc writeBytes*(b: Buffer; src: openArray[byte]) =
  if src.len == 0: return
  b.reserve(src.len)
  for i in 0 ..< src.len:
    b.data[b.pos + i] = src[i]
  b.pos += src.len

proc writeByte*(b: Buffer; v: byte) =
  b.reserve(1)
  b.data[b.pos] = v
  inc b.pos

proc readBytes*(b: Buffer; n: int): seq[byte] =
  if n < 0: raise newException(BufferRangeError, "negative read")
  if b.pos + n > b.data.len:
    raise newException(BufferRangeError,
      "read past end: pos=" & $b.pos & " n=" & $n & " len=" & $b.data.len)
  result = newSeq[byte](n)
  for i in 0 ..< n:
    result[i] = b.data[b.pos + i]
  b.pos += n

proc readByte*(b: Buffer): byte =
  if b.pos >= b.data.len:
    raise newException(BufferRangeError, "read past end")
  result = b.data[b.pos]
  inc b.pos

proc peekByte*(b: Buffer; offset = 0): byte =
  if b.pos + offset >= b.data.len:
    raise newException(BufferRangeError, "peek past end")
  result = b.data[b.pos + offset]

proc bytes*(b: Buffer): seq[byte] =
  ## Return a copy of the entire buffer (irrespective of cursor).
  result = b.data

proc consumed*(b: Buffer): seq[byte] =
  ## Bytes written so far (``0 ..< pos``).
  result = b.data[0 ..< b.pos]

# --- NDR alignment helpers --------------------------------------------------

proc alignTo*(b: Buffer; n: int) =
  ## Advance ``pos`` so it is a multiple of ``n``; pad with zero bytes on
  ## write, or just move the cursor on read. ``n`` must be a power of two
  ## in 1, 2, 4, 8.
  doAssert n in {1, 2, 4, 8}, "alignment must be 1/2/4/8 (got " & $n & ")"
  let mask = n - 1
  let pad = (-b.pos) and mask
  if pad == 0: return
  if b.pos + pad > b.data.len:
    # writing past end → grow and zero-fill
    b.reserve(pad)
  b.pos += pad

proc alignedPos*(pos, n: int): int {.inline.} =
  let mask = n - 1
  result = (pos + mask) and not mask

# --- Debug ------------------------------------------------------------------

proc hex*(b: Buffer): string =
  ## Hex dump of the entire buffer.
  result = newStringOfCap(b.data.len * 2)
  for x in b.data:
    result.add toHex(int(x), 2)
