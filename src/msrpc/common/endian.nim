## endian.nim — fixed-width little-/big-endian read/write on Buffer.
##
## All MS-RPC payloads we produce are little-endian (DREP byte 0 = 0x10).
## BE helpers are kept for ASN.1 / DER and the occasional NRPC field.

import buffers

# --- writers ---------------------------------------------------------------

proc writeU8*(b: Buffer; v: uint8) {.inline.} = b.writeByte(v)
proc writeI8*(b: Buffer; v: int8)  {.inline.} = b.writeByte(cast[uint8](v))

proc writeU16LE*(b: Buffer; v: uint16) =
  b.reserve(2)
  b.data[b.pos]     = byte(v and 0xff'u16)
  b.data[b.pos + 1] = byte((v shr 8) and 0xff'u16)
  b.pos += 2

proc writeU32LE*(b: Buffer; v: uint32) =
  b.reserve(4)
  b.data[b.pos]     = byte(v and 0xff'u32)
  b.data[b.pos + 1] = byte((v shr 8)  and 0xff'u32)
  b.data[b.pos + 2] = byte((v shr 16) and 0xff'u32)
  b.data[b.pos + 3] = byte((v shr 24) and 0xff'u32)
  b.pos += 4

proc writeU64LE*(b: Buffer; v: uint64) =
  b.reserve(8)
  for i in 0 ..< 8:
    b.data[b.pos + i] = byte((v shr (i * 8)) and 0xff'u64)
  b.pos += 8

proc writeI16LE*(b: Buffer; v: int16) {.inline.} = b.writeU16LE(cast[uint16](v))
proc writeI32LE*(b: Buffer; v: int32) {.inline.} = b.writeU32LE(cast[uint32](v))
proc writeI64LE*(b: Buffer; v: int64) {.inline.} = b.writeU64LE(cast[uint64](v))

proc writeU16BE*(b: Buffer; v: uint16) =
  b.reserve(2)
  b.data[b.pos]     = byte((v shr 8) and 0xff'u16)
  b.data[b.pos + 1] = byte(v and 0xff'u16)
  b.pos += 2

proc writeU32BE*(b: Buffer; v: uint32) =
  b.reserve(4)
  b.data[b.pos]     = byte((v shr 24) and 0xff'u32)
  b.data[b.pos + 1] = byte((v shr 16) and 0xff'u32)
  b.data[b.pos + 2] = byte((v shr 8)  and 0xff'u32)
  b.data[b.pos + 3] = byte(v and 0xff'u32)
  b.pos += 4

proc writeU64BE*(b: Buffer; v: uint64) =
  b.reserve(8)
  for i in 0 ..< 8:
    b.data[b.pos + i] = byte((v shr ((7 - i) * 8)) and 0xff'u64)
  b.pos += 8

# --- readers ---------------------------------------------------------------

proc readU8*(b: Buffer): uint8 {.inline.} = b.readByte()
proc readI8*(b: Buffer): int8  {.inline.} = cast[int8](b.readByte())

proc readU16LE*(b: Buffer): uint16 =
  if b.pos + 2 > b.data.len:
    raise newException(BufferRangeError, "readU16LE past end")
  result = uint16(b.data[b.pos]) or (uint16(b.data[b.pos + 1]) shl 8)
  b.pos += 2

proc readU32LE*(b: Buffer): uint32 =
  if b.pos + 4 > b.data.len:
    raise newException(BufferRangeError, "readU32LE past end")
  result =
    uint32(b.data[b.pos]) or
    (uint32(b.data[b.pos + 1]) shl 8) or
    (uint32(b.data[b.pos + 2]) shl 16) or
    (uint32(b.data[b.pos + 3]) shl 24)
  b.pos += 4

proc readU64LE*(b: Buffer): uint64 =
  if b.pos + 8 > b.data.len:
    raise newException(BufferRangeError, "readU64LE past end")
  result = 0'u64
  for i in 0 ..< 8:
    result = result or (uint64(b.data[b.pos + i]) shl (i * 8))
  b.pos += 8

proc readI16LE*(b: Buffer): int16 {.inline.} = cast[int16](b.readU16LE())
proc readI32LE*(b: Buffer): int32 {.inline.} = cast[int32](b.readU32LE())
proc readI64LE*(b: Buffer): int64 {.inline.} = cast[int64](b.readU64LE())

proc readU16BE*(b: Buffer): uint16 =
  if b.pos + 2 > b.data.len:
    raise newException(BufferRangeError, "readU16BE past end")
  result = (uint16(b.data[b.pos]) shl 8) or uint16(b.data[b.pos + 1])
  b.pos += 2

proc readU32BE*(b: Buffer): uint32 =
  if b.pos + 4 > b.data.len:
    raise newException(BufferRangeError, "readU32BE past end")
  result =
    (uint32(b.data[b.pos]) shl 24) or
    (uint32(b.data[b.pos + 1]) shl 16) or
    (uint32(b.data[b.pos + 2]) shl 8) or
    uint32(b.data[b.pos + 3])
  b.pos += 4

proc readU64BE*(b: Buffer): uint64 =
  if b.pos + 8 > b.data.len:
    raise newException(BufferRangeError, "readU64BE past end")
  result = 0'u64
  for i in 0 ..< 8:
    result = (result shl 8) or uint64(b.data[b.pos + i])
  b.pos += 8
