## sid.nim — MS-DTYP §2.4.2 SID (Security Identifier).
##
## Wire layout::
##
##   Revision        u8       (always 1)
##   SubAuthCount    u8       (0..15)
##   IdentAuth       [6]u8    big-endian 48-bit
##   SubAuthority    u32[N]   little-endian, N == SubAuthCount

import std/strutils
import buffers, endian

const
  SidRevision* = 1'u8
  MaxSubAuthorities* = 15

type
  Sid* = object
    revision*: uint8
    identifierAuthority*: array[6, byte]
    subAuthority*: seq[uint32]

  SidParseError* = object of CatchableError

proc subAuthCount*(s: Sid): int {.inline.} = s.subAuthority.len

proc identAuthority*(s: Sid): uint64 =
  ## 48-bit identifier authority read as a single integer (big-endian).
  for b in s.identifierAuthority:
    result = (result shl 8) or uint64(b)

proc setIdentAuthority*(s: var Sid; v: uint64) =
  ## ``v`` must fit in 48 bits.
  doAssert v <= 0xFFFFFFFFFFFF'u64
  for i in 0 ..< 6:
    s.identifierAuthority[5 - i] = byte((v shr (i * 8)) and 0xff'u64)

proc `==`*(a, b: Sid): bool =
  a.revision == b.revision and
    a.identifierAuthority == b.identifierAuthority and
    a.subAuthority == b.subAuthority

# --- text form ------------------------------------------------------------

proc `$`*(s: Sid): string =
  ## Canonical "S-R-I[-Subs]" form. The identifier authority is decimal
  ## when ≤ 2^32-1, else hex (matches Windows convention).
  result = "S-" & $s.revision & "-"
  let ia = s.identAuthority
  if ia >= 0x1_0000_0000'u64:
    result.add "0x" & toHex(BiggestInt(ia), 12)
  else:
    result.add $ia
  for sub in s.subAuthority:
    result.add '-'
    result.add $sub

proc parseSid*(text: string): Sid =
  ## Parse canonical SID text. Accepts both ``S-1-5-...`` and lowercase ``s-...``.
  let raw = text.strip()
  if raw.len < 5 or (raw[0] notin {'S', 's'}) or raw[1] != '-':
    raise newException(SidParseError, "missing 'S-' prefix")
  let parts = raw[2 .. ^1].split('-')
  if parts.len < 2:
    raise newException(SidParseError, "need at least revision and authority")
  try:
    result.revision = uint8(parseInt(parts[0]))
    let authStr = parts[1]
    let ia =
      if authStr.startsWith("0x") or authStr.startsWith("0X"):
        uint64(parseHexInt(authStr[2 .. ^1]))
      else:
        uint64(parseBiggestUInt(authStr))
    result.setIdentAuthority(ia)
    if parts.len - 2 > MaxSubAuthorities:
      raise newException(SidParseError, "too many sub-authorities")
    for i in 2 ..< parts.len:
      result.subAuthority.add uint32(parseBiggestUInt(parts[i]))
  except ValueError as e:
    raise newException(SidParseError, e.msg)

# --- wire form ------------------------------------------------------------

proc writeWire*(b: Buffer; s: Sid) =
  if s.subAuthority.len > MaxSubAuthorities:
    raise newException(SidParseError, "too many sub-authorities to marshal")
  b.writeByte(s.revision)
  b.writeByte(uint8(s.subAuthority.len))
  for x in s.identifierAuthority: b.writeByte(x)
  for sub in s.subAuthority: b.writeU32LE(sub)

proc readWire*(b: Buffer): Sid =
  result.revision = b.readByte()
  let count = int(b.readByte())
  if count > MaxSubAuthorities:
    raise newException(SidParseError, "sid sub-auth count > 15")
  for i in 0 ..< 6:
    result.identifierAuthority[i] = b.readByte()
  result.subAuthority = newSeq[uint32](count)
  for i in 0 ..< count:
    result.subAuthority[i] = b.readU32LE()

proc toWire*(s: Sid): seq[byte] =
  let b = newBuffer(8 + 4 * s.subAuthority.len)
  b.writeWire(s)
  result = b.consumed

proc fromWire*(data: openArray[byte]): Sid =
  let b = newBuffer(data)
  result = b.readWire()

proc wireLen*(s: Sid): int {.inline.} = 8 + 4 * s.subAuthority.len
