## pac.nim — MS-PAC Privilege Attribute Certificate container + simple buffers.
##
## The PAC travels inside a Kerberos ticket's authorization data and carries
## the user's logon information (SIDs, group RIDs), client name, and the two
## checksums the KDC and server use to validate it.
##
## This module decodes/encodes the ``PACTYPE`` container and the non-NDR
## buffers (client info, signatures). The big NDR-marshalled
## ``KERB_VALIDATION_INFO`` (logon info, buffer type 1) is handled separately.
##
## The PAC is little-endian throughout (unlike ccache/keytab).
##
## Reference: MS-PAC §2.3–2.8. Buffer types and layout cross-checked against
## impacket (``impacket.krb5.pac``) and TrustedSec Titanis (``PacBufferType.cs``,
## ``PacStructs.cs``); the container is byte-validated against an impacket-built PAC.

import msrpc/common/buffers
import msrpc/common/endian
import msrpc/common/unicode

# --- buffer type tags (MS-PAC §2.4) -----------------------------------------

const
  PacLogonInfo*          = 0x01'u32   ## KERB_VALIDATION_INFO (NDR)
  PacCredentialInfo*     = 0x02'u32
  PacServerChecksum*     = 0x06'u32   ## PAC_SIGNATURE_DATA
  PacKdcChecksum*        = 0x07'u32   ## PAC_SIGNATURE_DATA
  PacClientInfo*         = 0x0A'u32   ## PAC_CLIENT_INFO
  PacDelegationInfo*     = 0x0B'u32
  PacUpnDnsInfo*         = 0x0C'u32
  PacClientClaims*       = 0x0D'u32
  PacDeviceInfo*         = 0x0E'u32
  PacDeviceClaims*       = 0x0F'u32
  PacTicketChecksum*     = 0x10'u32
  PacAttributesInfo*     = 0x11'u32
  PacRequestorSid*       = 0x12'u32
  PacExtendedKdcChecksum* = 0x13'u32
  PacRequestorGuid*      = 0x14'u32

type
  PacError* = object of CatchableError

  PacInfoBuffer* = object
    ulType*: uint32
    data*: seq[byte]      ## the raw buffer bytes (``cbBufferSize`` long)

  Pac* = object
    version*: uint32      ## PACTYPE.Version (must be 0)
    buffers*: seq[PacInfoBuffer]

proc fail(msg: string) {.noreturn.} =
  raise newException(PacError, msg)

proc align8(n: int): int {.inline.} = (n + 7) and not 7

# --- container (PACTYPE) ----------------------------------------------------

proc parsePac*(data: openArray[byte]): Pac =
  ## Parse a PACTYPE container into its info buffers. Raises ``PacError``.
  let b = newBuffer(data)
  try:
    let cBuffers = b.readU32LE()
    result.version = b.readU32LE()
    if result.version != 0:
      fail("unexpected PAC version " & $result.version & " (expected 0)")
    if cBuffers > uint32(b.remaining div 16) + 1:
      fail("implausible buffer count " & $cBuffers)
    var descs: seq[tuple[ulType: uint32, size: int, offset: int]]
    for _ in 0'u32 ..< cBuffers:
      let ulType = b.readU32LE()
      let size = int(b.readU32LE())
      let offset = int(b.readU64LE())
      descs.add (ulType, size, offset)
    for d in descs:
      if d.offset < 0 or d.size < 0 or d.offset + d.size > data.len:
        fail("buffer (type " & $d.ulType & ") at " & $d.offset & "+" & $d.size &
             " runs past the " & $data.len & "-byte PAC")
      result.buffers.add PacInfoBuffer(ulType: d.ulType,
        data: @(data.toOpenArray(d.offset, d.offset + d.size - 1)))
  except BufferRangeError as e:
    fail("truncated or malformed PAC: " & e.msg)

proc encodePac*(pac: Pac): seq[byte] =
  ## Serialize a PAC. Buffers are laid out contiguously in array order, each
  ## 8-byte aligned (zero-padded) as MS-PAC requires.
  let hdrLen = 8 + 16 * pac.buffers.len
  var off = hdrLen
  var offsets: seq[int]
  for buf in pac.buffers:
    offsets.add off
    off += align8(buf.data.len)

  let b = newBuffer()
  b.writeU32LE(uint32(pac.buffers.len))
  b.writeU32LE(pac.version)
  for i, buf in pac.buffers:
    b.writeU32LE(buf.ulType)
    b.writeU32LE(uint32(buf.data.len))
    b.writeU64LE(uint64(offsets[i]))
  for buf in pac.buffers:
    b.writeBytes(buf.data)
    for _ in buf.data.len ..< align8(buf.data.len):
      b.writeByte(0)
  result = b.bytes

proc findBuffer*(pac: Pac; ulType: uint32): seq[byte] =
  ## Raw bytes of the first buffer with ``ulType``; empty seq if absent.
  for buf in pac.buffers:
    if buf.ulType == ulType:
      return buf.data
  return @[]

proc hasBuffer*(pac: Pac; ulType: uint32): bool =
  for buf in pac.buffers:
    if buf.ulType == ulType: return true
  false

# --- PAC_CLIENT_INFO (MS-PAC §2.7) ------------------------------------------

type
  PacClientInfo_t* = object
    clientId*: uint64     ## FILETIME of the client's TGT request
    name*: string         ## account name (UTF-16LE on the wire)

proc parseClientInfo*(buf: openArray[byte]): PacClientInfo_t =
  let b = newBuffer(buf)
  try:
    result.clientId = b.readU64LE()
    let nameLen = int(b.readU16LE())
    result.name = fromUtf16Bytes(b.readBytes(nameLen))
  except BufferRangeError as e:
    fail("malformed PAC_CLIENT_INFO: " & e.msg)

proc encodeClientInfo*(ci: PacClientInfo_t): seq[byte] =
  let nameBytes = toUtf16Bytes(ci.name)
  let b = newBuffer()
  b.writeU64LE(ci.clientId)
  b.writeU16LE(uint16(nameBytes.len))
  b.writeBytes(nameBytes)
  result = b.bytes

# --- PAC_SIGNATURE_DATA (MS-PAC §2.8) ---------------------------------------

type
  PacSignature* = object
    signatureType*: int32   ## a Kerberos checksum type (e.g. 16 = HMAC-SHA1-96-AES256)
    signature*: seq[byte]

proc parseSignature*(buf: openArray[byte]): PacSignature =
  let b = newBuffer(buf)
  try:
    result.signatureType = cast[int32](b.readU32LE())
    result.signature = b.readBytes(b.remaining)
  except BufferRangeError as e:
    fail("malformed PAC_SIGNATURE_DATA: " & e.msg)

proc encodeSignature*(sig: PacSignature): seq[byte] =
  let b = newBuffer()
  b.writeU32LE(cast[uint32](sig.signatureType))
  b.writeBytes(sig.signature)
  result = b.bytes
