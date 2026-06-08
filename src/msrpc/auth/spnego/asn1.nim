## auth/spnego/asn1.nim — minimal ASN.1 DER encoder/parser.
##
## Just enough to build NegTokenInit / NegTokenResp and the GSS-API
## outer wrap. We use definite-length form everywhere and lean on the
## fact that SPNEGO uses a small fixed set of tags.

import ../../common/buffers

type
  DerError* = object of CatchableError

const
  tagSequence*    = 0x30'u8
  tagOctetString* = 0x04'u8
  tagOid*         = 0x06'u8
  tagEnumerated*  = 0x0a'u8
  tagBitString*   = 0x03'u8

proc ctxConstructed*(n: int): byte {.inline.} =
  ## Context-specific constructed tag [n] (e.g. [0] = 0xA0).
  result = byte(0xA0 or n)

proc appConstructed*(n: int): byte {.inline.} =
  ## Application-class constructed tag [APPLICATION n] (GSS-API uses 0).
  result = byte(0x60 or n)

# --- length encoding ----------------------------------------------------

proc derWriteLen*(b: Buffer; n: int) =
  if n < 0x80:
    b.writeByte(byte(n))
  elif n <= 0xFF:
    b.writeByte(0x81'u8); b.writeByte(byte(n))
  elif n <= 0xFFFF:
    b.writeByte(0x82'u8)
    b.writeByte(byte((n shr 8) and 0xff))
    b.writeByte(byte(n and 0xff))
  elif n <= 0xFFFFFF:
    b.writeByte(0x83'u8)
    b.writeByte(byte((n shr 16) and 0xff))
    b.writeByte(byte((n shr 8) and 0xff))
    b.writeByte(byte(n and 0xff))
  else:
    raise newException(DerError, "DER length too large: " & $n)

proc derReadLen*(b: Buffer): int =
  let first = b.readByte()
  if (first and 0x80) == 0:
    return int(first)
  let n = int(first and 0x7F)
  if n == 0 or n > 4:
    raise newException(DerError, "indefinite or oversized DER length")
  result = 0
  for _ in 0 ..< n:
    result = (result shl 8) or int(b.readByte())

# --- TLV wrapper helper -------------------------------------------------

proc derTLV*(tag: byte; value: openArray[byte]): seq[byte] =
  let inner = newBuffer()
  inner.writeByte(tag)
  inner.derWriteLen(value.len)
  inner.writeBytes(value)
  result = inner.consumed

proc derReadTag*(b: Buffer; expected: byte): int =
  let got = b.readByte()
  if got != expected:
    raise newException(DerError,
      "DER tag mismatch: expected 0x" & $expected & " got 0x" & $got)
  result = b.derReadLen()

# --- OID -------------------------------------------------------------

proc derEncodeOid*(arcs: openArray[int]): seq[byte] =
  ## DER-encode an OID from its dotted form. The first two arcs are
  ## combined as 40*a + b; subsequent arcs use base-128 with the high
  ## bit set on every byte except the last.
  if arcs.len < 2:
    raise newException(DerError, "OID needs at least 2 arcs")
  let body = newBuffer()
  body.writeByte(byte(arcs[0] * 40 + arcs[1]))
  for i in 2 ..< arcs.len:
    let v = arcs[i]
    if v < 0:
      raise newException(DerError, "negative OID arc")
    if v < 0x80:
      body.writeByte(byte(v))
    else:
      # Find required number of base-128 digits.
      var digits: seq[byte] = @[]
      var x = v
      while x > 0:
        digits.add byte(x and 0x7F)
        x = x shr 7
      # Reverse order, set high bit on all but last.
      for k in countdown(digits.high, 1):
        body.writeByte(digits[k] or 0x80'u8)
      body.writeByte(digits[0])
  result = derTLV(tagOid, body.consumed)

proc derParseOid*(b: Buffer): seq[int] =
  let length = b.derReadTag(tagOid)
  let endPos = b.pos + length
  result = @[]
  if length == 0: return
  let first = int(b.readByte())
  result.add first div 40
  result.add first mod 40
  while b.pos < endPos:
    var v = 0
    while true:
      let c = b.readByte()
      v = (v shl 7) or int(c and 0x7F)
      if (c and 0x80) == 0: break
    result.add v

proc derParseOctetString*(b: Buffer): seq[byte] =
  let length = b.derReadTag(tagOctetString)
  result = b.readBytes(length)

# --- known SPNEGO / NTLM OIDs (for convenience) ---------------------

const
  SpnegoOidArcs*  = [1, 3, 6, 1, 5, 5, 2]
  NtlmsspOidArcs* = [1, 3, 6, 1, 4, 1, 311, 2, 2, 10]
  KerberosOidArcs* = [1, 2, 840, 113554, 1, 2, 2]
