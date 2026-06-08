## ldap/ber.nim — BER encoder/parser primitives for LDAP (RFC 4511).
##
## We use the same definite-length DER we already built for SPNEGO and
## extend with LDAP-specific tag constants and integer/boolean/enum
## helpers.

import ../common/buffers
import ../auth/spnego/asn1

export asn1.derWriteLen, asn1.derReadLen, asn1.derTLV, asn1.derReadTag
export asn1.derEncodeOid, asn1.derParseOid
export asn1.derParseOctetString
export asn1.tagSequence, asn1.tagOctetString, asn1.tagOid
export asn1.tagBitString, asn1.tagEnumerated
export asn1.appConstructed, asn1.ctxConstructed
export asn1.DerError

const
  tagBoolean*    = 0x01'u8
  tagInteger*    = 0x02'u8
  tagNull*       = 0x05'u8
  tagSet*        = 0x31'u8

proc ctxPrimitive*(n: int): byte {.inline.} =
  ## Context-specific primitive [n] (no "constructed" bit).
  result = byte(0x80 or n)

proc appPrimitive*(n: int): byte {.inline.} =
  result = byte(0x40 or n)

proc berEncodeInt*(v: int64): seq[byte] =
  if v == 0:
    return derTLV(tagInteger, @[0'u8])
  var bytes: seq[byte] = @[]
  var x = v
  if x > 0:
    while x > 0:
      bytes.insert(byte(x and 0xff), 0)
      x = x shr 8
    if (bytes[0] and 0x80) != 0:
      bytes.insert(0'u8, 0)
  else:
    var nbytes = 1
    var probe = x
    while probe < -128 or probe >= 128:
      inc nbytes; probe = probe shr 8
    bytes = newSeq[byte](nbytes)
    for i in 0 ..< nbytes:
      bytes[nbytes - 1 - i] = byte(x and 0xff)
      x = x shr 8
  result = derTLV(tagInteger, bytes)

proc berParseInt*(b: Buffer): int64 =
  let length = b.derReadTag(tagInteger)
  if length == 0: return 0
  let bytes = b.readBytes(length)
  result = 0
  if (bytes[0] and 0x80) != 0:
    result = -1
  for x in bytes:
    result = (result shl 8) or int64(x)

proc berEnumerated*(v: int): seq[byte] =
  result = berEncodeInt(int64(v))
  result[0] = tagEnumerated

proc berEncodeBool*(v: bool): seq[byte] =
  derTLV(tagBoolean, @[if v: 0xFF'u8 else: 0x00'u8])
