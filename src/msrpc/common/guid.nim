## guid.nim — UUID/GUID type with string and wire parsers.
##
## Microsoft GUIDs are mixed-endian on the wire: the first three groups
## (Data1=u32, Data2=u16, Data3=u16) are little-endian; the last 8 bytes
## are written in order. Big-endian "RFC 4122" form is also provided.

import std/strutils
import buffers, endian

type
  Uuid* = object
    data1*: uint32
    data2*: uint16
    data3*: uint16
    data4*: array[8, byte]

  GuidParseError* = object of CatchableError

const ZeroUuid* = Uuid()

proc `==`*(a, b: Uuid): bool =
  a.data1 == b.data1 and a.data2 == b.data2 and a.data3 == b.data3 and
    a.data4 == b.data4

proc isZero*(u: Uuid): bool {.inline.} = u == ZeroUuid

proc `$`*(u: Uuid): string =
  ## Standard 8-4-4-4-12 lowercase form.
  result = newStringOfCap(36)
  result.add toHex(int(u.data1), 8).toLowerAscii
  result.add '-'
  result.add toHex(int(u.data2), 4).toLowerAscii
  result.add '-'
  result.add toHex(int(u.data3), 4).toLowerAscii
  result.add '-'
  result.add toHex(int(u.data4[0]), 2).toLowerAscii
  result.add toHex(int(u.data4[1]), 2).toLowerAscii
  result.add '-'
  for i in 2 .. 7:
    result.add toHex(int(u.data4[i]), 2).toLowerAscii

proc parseUuid*(s: string): Uuid =
  ## Accept ``xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`` and ``{...}`` forms.
  var t = s.strip()
  if t.len > 0 and t[0] == '{' and t[^1] == '}':
    t = t[1 ..< t.len - 1]
  if t.len != 36:
    raise newException(GuidParseError, "uuid length: " & $t.len)
  for i, ch in t:
    if i in {8, 13, 18, 23}:
      if ch != '-':
        raise newException(GuidParseError, "expected '-' at " & $i)
    elif ch notin HexDigits:
      raise newException(GuidParseError, "non-hex char at " & $i)
  try:
    result.data1 = uint32(parseHexInt(t[0 ..< 8]))
    result.data2 = uint16(parseHexInt(t[9 ..< 13]))
    result.data3 = uint16(parseHexInt(t[14 ..< 18]))
    result.data4[0] = byte(parseHexInt(t[19 ..< 21]))
    result.data4[1] = byte(parseHexInt(t[21 ..< 23]))
    for i in 0 ..< 6:
      result.data4[2 + i] = byte(parseHexInt(t[24 + i*2 ..< 26 + i*2]))
  except ValueError as e:
    raise newException(GuidParseError, e.msg)

# Wire formats -------------------------------------------------------------

proc writeWire*(b: Buffer; u: Uuid) =
  ## Microsoft on-wire form (mixed-endian, 16 bytes).
  b.writeU32LE(u.data1)
  b.writeU16LE(u.data2)
  b.writeU16LE(u.data3)
  for x in u.data4: b.writeByte(x)

proc readWire*(b: Buffer): Uuid =
  result.data1 = b.readU32LE()
  result.data2 = b.readU16LE()
  result.data3 = b.readU16LE()
  for i in 0 ..< 8:
    result.data4[i] = b.readByte()

proc toWire*(u: Uuid): seq[byte] =
  let b = newBuffer(16)
  b.writeWire(u)
  result = b.consumed

proc fromWire*(data: openArray[byte]): Uuid =
  let b = newBuffer(data)
  result = b.readWire()
