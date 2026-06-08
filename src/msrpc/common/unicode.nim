## unicode.nim — UTF-16LE conversion and MS-DTYP RPC_UNICODE_STRING.
##
## Nim strings hold UTF-8. On the wire, NDR and SMB use UTF-16LE.
## Surrogate pairs are handled symmetrically. Lone surrogates round-trip
## as U+FFFD (replacement) on decode to avoid producing invalid UTF-8.

import buffers, endian

type
  Utf16DecodeError* = object of CatchableError

# --- encoders -------------------------------------------------------------

proc toUtf16Units*(s: string): seq[uint16] =
  ## Decode UTF-8 → sequence of UTF-16 code units.
  result = newSeqOfCap[uint16](s.len)
  var i = 0
  while i < s.len:
    let b0 = uint32(s[i].ord)
    var cp: uint32
    var n: int
    if (b0 and 0x80) == 0:
      cp = b0; n = 1
    elif (b0 and 0xE0) == 0xC0:
      cp = b0 and 0x1F; n = 2
    elif (b0 and 0xF0) == 0xE0:
      cp = b0 and 0x0F; n = 3
    elif (b0 and 0xF8) == 0xF0:
      cp = b0 and 0x07; n = 4
    else:
      raise newException(Utf16DecodeError, "invalid utf-8 leading byte at " & $i)
    if i + n > s.len:
      raise newException(Utf16DecodeError, "utf-8 truncated at " & $i)
    for k in 1 ..< n:
      let cb = uint32(s[i + k].ord)
      if (cb and 0xC0) != 0x80:
        raise newException(Utf16DecodeError, "utf-8 continuation byte at " & $(i+k))
      cp = (cp shl 6) or (cb and 0x3F)
    i += n
    if cp <= 0xFFFF:
      result.add uint16(cp)
    else:
      let v = cp - 0x10000
      result.add uint16(0xD800 or (v shr 10))
      result.add uint16(0xDC00 or (v and 0x3FF))

proc toUtf16Bytes*(s: string): seq[byte] =
  ## UTF-16LE bytes (no BOM, no NUL terminator).
  let units = toUtf16Units(s)
  result = newSeq[byte](units.len * 2)
  for i, u in units:
    result[i*2]     = byte(u and 0xff)
    result[i*2 + 1] = byte((u shr 8) and 0xff)

# --- decoders -------------------------------------------------------------

proc fromUtf16Units*(units: openArray[uint16]): string =
  result = newStringOfCap(units.len)
  var i = 0
  while i < units.len:
    var cp: uint32
    let u = units[i]
    if u >= 0xD800'u16 and u <= 0xDBFF'u16:
      if i + 1 < units.len and units[i+1] >= 0xDC00'u16 and units[i+1] <= 0xDFFF'u16:
        cp = 0x10000'u32 +
             ((uint32(u) - 0xD800'u32) shl 10) +
             (uint32(units[i+1]) - 0xDC00'u32)
        inc i, 2
      else:
        cp = 0xFFFD
        inc i
    elif u >= 0xDC00'u16 and u <= 0xDFFF'u16:
      cp = 0xFFFD
      inc i
    else:
      cp = uint32(u)
      inc i
    if cp < 0x80:
      result.add char(cp)
    elif cp < 0x800:
      result.add char(0xC0 or (cp shr 6))
      result.add char(0x80 or (cp and 0x3F))
    elif cp < 0x10000:
      result.add char(0xE0 or (cp shr 12))
      result.add char(0x80 or ((cp shr 6) and 0x3F))
      result.add char(0x80 or (cp and 0x3F))
    else:
      result.add char(0xF0 or (cp shr 18))
      result.add char(0x80 or ((cp shr 12) and 0x3F))
      result.add char(0x80 or ((cp shr 6) and 0x3F))
      result.add char(0x80 or (cp and 0x3F))

proc fromUtf16Bytes*(data: openArray[byte]): string =
  if data.len mod 2 != 0:
    raise newException(Utf16DecodeError, "utf-16 byte length not even")
  var units = newSeq[uint16](data.len div 2)
  for i in 0 ..< units.len:
    units[i] = uint16(data[i*2]) or (uint16(data[i*2 + 1]) shl 8)
  result = fromUtf16Units(units)

# --- Buffer convenience --------------------------------------------------

proc writeUtf16LE*(b: Buffer; s: string; nullTerminate = false) =
  let bytes = toUtf16Bytes(s)
  b.writeBytes(bytes)
  if nullTerminate:
    b.writeU16LE(0)

proc readUtf16LE*(b: Buffer; codeUnitCount: int): string =
  ## Read ``codeUnitCount`` UTF-16LE units (each 2 bytes) starting at ``pos``.
  var units = newSeq[uint16](codeUnitCount)
  for i in 0 ..< codeUnitCount:
    units[i] = b.readU16LE()
  result = fromUtf16Units(units)
