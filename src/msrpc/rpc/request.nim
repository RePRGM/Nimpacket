## rpc/request.nim — Request / Response PDUs.
##
## C706 §12.6.4 + MS-RPCE §2.2.2.4.
##
## REQUEST body (after the 16-byte header):
##   alloc_hint  u32       caller's hint at total stub size
##   p_cont_id   u16       presentation context to dispatch to
##   opnum       u16       method index
##   (object_id  uuid)     present only if PFC_OBJECT_UUID flag is set
##   stub_data   bytes
##   (auth pad + sec_trailer + auth_verifier  iff auth_length > 0)
##
## RESPONSE body:
##   alloc_hint    u32
##   p_cont_id     u16
##   cancel_count  u8
##   reserved      u8
##   stub_data     bytes

import ../common/[buffers, endian, guid]
import pdu

type
  RequestPdu* = object
    callId*: uint32
    contextId*: uint16
    opnum*: uint16
    objectUuid*: Uuid           ## only used if ``hasObject``
    hasObject*: bool
    stub*: seq[byte]
    authVerifier*: seq[byte]    ## sec_trailer + auth data, empty if none

  ResponsePdu* = object
    callId*: uint32
    contextId*: uint16
    cancelCount*: uint8
    stub*: seq[byte]
    authVerifier*: seq[byte]

# --- helpers ---------------------------------------------------------------

proc requestBodyLen(p: RequestPdu): int =
  result = 4 + 2 + 2 + p.stub.len + p.authVerifier.len
  if p.hasObject: result += 16

proc responseBodyLen(p: ResponsePdu): int =
  4 + 2 + 1 + 1 + p.stub.len + p.authVerifier.len

# --- REQUEST ---------------------------------------------------------------

proc buildRequest*(p: RequestPdu;
                   flags: PfcFlags = {pfcFirstFrag, pfcLastFrag}): seq[byte] =
  var f = flags
  if p.hasObject: f.incl pfcObjectUuid
  var hdr = defaultHeader(ptRequest, p.callId, f)
  hdr.fragLen = uint16(HeaderLen + requestBodyLen(p))
  hdr.authLen = uint16(p.authVerifier.len)
  # Note: sec_trailer length is included in authVerifier (caller's
  # responsibility); authLen counts only the verifier bytes after the
  # sec_trailer per MS-RPCE — see ``writeWithSecTrailer`` for the case
  # that builds these from a SecTrailer + raw verifier.
  let b = newBuffer()
  b.writeHeader(hdr)
  b.writeU32LE(uint32(p.stub.len))   # alloc_hint matches stub size
  b.writeU16LE(p.contextId)
  b.writeU16LE(p.opnum)
  if p.hasObject: b.writeWire(p.objectUuid)
  b.writeBytes(p.stub)
  b.writeBytes(p.authVerifier)
  result = b.consumed

proc parseRequest*(data: openArray[byte]): RequestPdu =
  let b = newBuffer(data)
  let hdr = b.readHeader()
  if hdr.pType != ptRequest:
    raise newException(ValueError, "not a REQUEST PDU")
  result.callId = hdr.callId
  discard b.readU32LE()           # alloc_hint
  result.contextId = b.readU16LE()
  result.opnum = b.readU16LE()
  result.hasObject = pfcObjectUuid in hdr.flags
  if result.hasObject:
    result.objectUuid = b.readWire()
  let stubLen = int(hdr.fragLen) - HeaderLen - 8 -
                (if result.hasObject: 16 else: 0) - int(hdr.authLen)
  if stubLen < 0:
    raise newException(ValueError, "negative stub length")
  result.stub = b.readBytes(stubLen)
  result.authVerifier = b.readBytes(int(hdr.authLen))

# --- RESPONSE --------------------------------------------------------------

proc buildResponse*(p: ResponsePdu;
                    flags: PfcFlags = {pfcFirstFrag, pfcLastFrag}): seq[byte] =
  var hdr = defaultHeader(ptResponse, p.callId, flags)
  hdr.fragLen = uint16(HeaderLen + responseBodyLen(p))
  hdr.authLen = uint16(p.authVerifier.len)
  let b = newBuffer()
  b.writeHeader(hdr)
  b.writeU32LE(uint32(p.stub.len))
  b.writeU16LE(p.contextId)
  b.writeByte(p.cancelCount)
  b.writeByte(0)
  b.writeBytes(p.stub)
  b.writeBytes(p.authVerifier)
  result = b.consumed

proc parseResponse*(data: openArray[byte]): ResponsePdu =
  let b = newBuffer(data)
  let hdr = b.readHeader()
  if hdr.pType != ptResponse:
    raise newException(ValueError, "not a RESPONSE PDU")
  result.callId = hdr.callId
  discard b.readU32LE()
  result.contextId = b.readU16LE()
  result.cancelCount = b.readByte()
  discard b.readByte()
  let stubLen = int(hdr.fragLen) - HeaderLen - 8 - int(hdr.authLen)
  if stubLen < 0:
    raise newException(ValueError, "negative stub length")
  result.stub = b.readBytes(stubLen)
  result.authVerifier = b.readBytes(int(hdr.authLen))

# --- FAULT (kept compact) -------------------------------------------------

type
  FaultPdu* = object
    callId*: uint32
    contextId*: uint16
    cancelCount*: uint8
    status*: uint32           ## Win32 / NTSTATUS / RPC fault code

proc buildFault*(p: FaultPdu): seq[byte] =
  var hdr = defaultHeader(ptFault, p.callId)
  hdr.fragLen = uint16(HeaderLen + 16)
  let b = newBuffer()
  b.writeHeader(hdr)
  b.writeU32LE(0)               # alloc_hint
  b.writeU16LE(p.contextId)
  b.writeByte(p.cancelCount)
  b.writeByte(0)
  b.writeU32LE(p.status)
  b.writeU32LE(0)               # reserved
  result = b.consumed

proc parseFault*(data: openArray[byte]): FaultPdu =
  let b = newBuffer(data)
  let hdr = b.readHeader()
  if hdr.pType != ptFault:
    raise newException(ValueError, "not a FAULT PDU")
  result.callId = hdr.callId
  discard b.readU32LE()
  result.contextId = b.readU16LE()
  result.cancelCount = b.readByte()
  discard b.readByte()
  result.status = b.readU32LE()
