import std/[tables, strutils, endians, sequtils, options, macros]

# ==================== Core Types ====================

type
  NDRVersion* = enum
    NDR20 = 0x00  # NDR 2.0
    
  NDRCharacterEncoding* = enum
    ASCII = 0x00
    EBCDIC = 0x01
    
  NDRFloatingPointRep* = enum
    IEEE = 0x00
    VAX = 0x01
    CRAY = 0x02
    IBM = 0x03
    
  NDRByteOrder* = enum
    BigEndian = 0x00
    LittleEndian = 0x10

  NDRDataRepresentation* = object
    integerRep*: NDRByteOrder
    characterRep*: NDRCharacterEncoding
    floatingPointRep*: NDRFloatingPointRep
    reserved*: uint8

  NDRBuffer* = ref object
    data*: seq[uint8]
    position*: int
    dataRep*: NDRDataRepresentation
    # For encoding
    referentId*: uint32
    deferredPointers*: seq[proc()]
    stringReferences*: Table[string, uint32]
    # For decoding
    pointerValues*: Table[uint32, int]  # referent ID -> buffer position
    deferredData*: int # Position where deferred data begins

  NDRError* = object of CatchableError

  # NDR type classifications
  NDRTypeKind* = enum
    ntkPrimitive
    ntkString
    ntkPointer
    ntkArray
    ntkStruct
    ntkUnion
    ntkPipe
    ntkInterface

  NDRAlignment* = enum
    Align1 = 1
    Align2 = 2
    Align4 = 4
    Align8 = 8

  absSyntaxID* = object
    ifUUID*: array[16, uint8]
    ifVersion*: uint16
    ifMinorVersion*: uint16

  presContextElement* = object
    contextID*: uint16
    numTransSyntaxes*: uint8
    padding*: uint8
    absSyntax*: absSyntaxID
    transSyntax*: absSyntaxID

  # RPC PDU Types
  PDUType* = enum
    ptRequest = 0
    ptPing = 1
    ptResponse = 2
    ptFault = 3
    ptBind = 11
    ptBindAck = 12
    ptBindNak = 13
    ptAlterContext = 14
    ptAlterContextResp = 15
    ptShutdown = 17
    ptCoCancel = 18
    ptOrphaned = 19

  # RPC PDU Flags
  PDUFlags* = enum
    pfFirstFrag = 0x01
    pfLastFrag = 0x02
    pfPending = 0x03
    pfFrag = 0x04
    pfNoFack = 0x08
    pfMaybe = 0x10
    pfIdempotent = 0x20
    pfBroadcast = 0x40

  UUID* = object
    data1*: uint32
    data2*: uint16
    data3*: uint16
    data4*: array[8, uint8]

  SyntaxID* = object
    uuid*: UUID
    version*: uint32
    
  PDUHeader* = object
    version*: uint8
    minorVersion*: uint8
    pType*: PDUType
    pFlags*: uint8
    dRep*: array[4, uint8]
    
    fragLength*: uint16
    authLength*: uint16
    callID*: uint32

  PDUBind* = object
    header*: PDUHeader
    maxXmitFrag*: uint16
    maxRecvFrag*: uint16
    assocGroupID*: uint32
    numContextElements*: uint8

  PDURequest* = object
    header*: PDUHeader
    allocHint*: uint32
    contextID*: uint16
    opNum*: uint16

# ==================== Buffer Operations ====================

proc newNDRBuffer*(dataRep: NDRDataRepresentation = NDRDataRepresentation(
  integerRep: LittleEndian,
  characterRep: ASCII,
  floatingPointRep: IEEE,
  reserved: 0
)): NDRBuffer =
  result = NDRBuffer(
    data: @[],
    position: 0,
    dataRep: dataRep,
    referentId: 0x20000,  # Start referent IDs at 0x20000
    deferredPointers: @[],
    stringReferences: initTable[string, uint32](),
    pointerValues: initTable[uint32, int](),
  )

proc align*(buf: NDRBuffer, alignment: NDRAlignment) =
  let alignValue = alignment.int
  let padding = (alignValue - (buf.position mod alignValue)) mod alignValue
  for i in 0..<padding:
    buf.data.add(0'u8)
    inc buf.position

proc writeBytes*(buf: NDRBuffer, bytes: openArray[uint8]) =
  buf.data.add(bytes)
  buf.position += bytes.len

proc readBytes*(buf: NDRBuffer, count: int): seq[uint8] =
  if buf.position + count > buf.data.len:
    raise newException(NDRError, "Buffer underrun")
  result = buf.data[buf.position..<buf.position + count]
  buf.position += count

proc peekUint32*(buf: NDRBuffer): uint32 =
  if buf.position + 4 > buf.data.len:
    raise newException(NDRError, "Buffer underrun")
  var bytes = buf.data[buf.position..<buf.position + 4]
  if buf.dataRep.integerRep == LittleEndian:
    littleEndian32(addr result, addr bytes[0])
  else:
    bigEndian32(addr result, addr bytes[0])

proc getNextReferentId*(buf: NDRBuffer): uint32 =
  result = buf.referentId
  inc buf.referentId

proc deferPointerEncoding*(buf: NDRBuffer, encoder: proc()) =
  buf.deferredPointers.add(encoder)

proc processDeferredPointers*(buf: NDRBuffer) =
  while buf.deferredPointers.len > 0:
    let encoder = buf.deferredPointers[0]
    buf.deferredPointers.delete(0)
    encoder()

# ==================== Primitive Type Encoding ====================
proc encodeUint8*(buf: NDRBuffer, value: uint8) =
  buf.writeBytes([value])

proc encodeUint16*(buf: NDRBuffer, value: uint16) =
  buf.align(Align2)
  var bytes: array[2, uint8]
  if buf.dataRep.integerRep == LittleEndian:
    littleEndian16(addr bytes[0], unsafeAddr value)
  else:
    bigEndian16(addr bytes[0], unsafeAddr value)
  buf.writeBytes(bytes)

proc encodeUint32*(buf: NDRBuffer, value: uint32) =
  buf.align(Align4)
  var bytes: array[4, uint8]
  if buf.dataRep.integerRep == LittleEndian:
    littleEndian32(addr bytes[0], unsafeAddr value)
  else:
    bigEndian32(addr bytes[0], unsafeAddr value)
  buf.writeBytes(bytes)

proc encodeUint64*(buf: NDRBuffer, value: uint64) =
  buf.align(Align8)
  var bytes: array[8, uint8]
  if buf.dataRep.integerRep == LittleEndian:
    littleEndian64(addr bytes[0], unsafeAddr value)
  else:
    bigEndian64(addr bytes[0], unsafeAddr value)
  buf.writeBytes(bytes)

proc encodeInt8*(buf: NDRBuffer, value: int8) =
  encodeUint8(buf, cast[uint8](value))

proc encodeInt16*(buf: NDRBuffer, value: int16) =
  encodeUint16(buf, cast[uint16](value))

proc encodeInt32*(buf: NDRBuffer, value: int32) =
  encodeUint32(buf, cast[uint32](value))

proc encodeInt64*(buf: NDRBuffer, value: int64) =
  encodeUint64(buf, cast[uint64](value))

proc encodeFloat32*(buf: NDRBuffer, value: float32) =
  buf.align(Align4)
  var bytes: array[4, uint8]
  copyMem(addr bytes[0], unsafeAddr value, 4)
  if buf.dataRep.integerRep != LittleEndian:
    # Swap bytes for big endian
    swap(bytes[0], bytes[3])
    swap(bytes[1], bytes[2])
  buf.writeBytes(bytes)

proc encodeFloat64*(buf: NDRBuffer, value: float64) =
  buf.align(Align8)
  var bytes: array[8, uint8]
  copyMem(addr bytes[0], unsafeAddr value, 8)
  if buf.dataRep.integerRep != LittleEndian:
    # Swap bytes for big endian
    for i in 0..<4:
      swap(bytes[i], bytes[7-i])
  buf.writeBytes(bytes)

proc encodeBool*(buf: NDRBuffer, value: bool) =
  encodeUint8(buf, if value: 1'u8 else: 0'u8)

proc encodeUint32NDR64*(buf: NDRBuffer, value: uint32) =
  ## Encode uint32 with NDR64 padding (8-byte alignment)
  encodeUint32(buf, value)
  encodeUint32(buf, 0)  # 4 bytes padding

proc encodeUint64NDR64*(buf: NDRBuffer, value: uint64) =
  ## Encode uint64 (already 8-byte aligned)
  encodeUint64(buf, value)

proc encodePointerNDR64*(buf: NDRBuffer, referentId: uint32) =
  ## Encode a pointer reference in NDR64 format
  encodeUint32(buf, referentId)
  encodeUint32(buf, 0)  # Upper 32 bits of 64-bit pointer

proc alignToNDR64*(buf: NDRBuffer) =
  ## Align buffer position to 8-byte boundary
  let alignment = buf.position mod 8
  if alignment != 0:
    for i in 0..<(8 - alignment):
      encodeUint8(buf, 0)
      
# ==================== Primitive Type Decoding ====================

proc decodeUint8*(buf: NDRBuffer): uint8 =
  let bytes = buf.readBytes(1)
  result = bytes[0]

proc decodeUint16*(buf: NDRBuffer): uint16 =
  buf.align(Align2)
  let bytes = buf.readBytes(2)
  if buf.dataRep.integerRep == LittleEndian:
    littleEndian16(addr result, unsafeAddr bytes[0])
  else:
    bigEndian16(addr result, unsafeAddr bytes[0])

proc decodeUint32*(buf: NDRBuffer): uint32 =
  buf.align(Align4)
  let bytes = buf.readBytes(4)
  if buf.dataRep.integerRep == LittleEndian:
    littleEndian32(addr result, unsafeAddr bytes[0])
  else:
    bigEndian32(addr result, unsafeAddr bytes[0])

proc decodeUint64*(buf: NDRBuffer): uint64 =
  buf.align(Align8)
  let bytes = buf.readBytes(8)
  if buf.dataRep.integerRep == LittleEndian:
    littleEndian64(addr result, unsafeAddr bytes[0])
  else:
    bigEndian64(addr result, unsafeAddr bytes[0])

proc decodeInt8*(buf: NDRBuffer): int8 =
  cast[int8](decodeUint8(buf))

proc decodeInt16*(buf: NDRBuffer): int16 =
  cast[int16](decodeUint16(buf))

proc decodeInt32*(buf: NDRBuffer): int32 =
  cast[int32](decodeUint32(buf))

proc decodeInt64*(buf: NDRBuffer): int64 =
  cast[int64](decodeUint64(buf))

proc decodeFloat32*(buf: NDRBuffer): float32 =
  buf.align(Align4)
  var bytes = buf.readBytes(4)
  if buf.dataRep.integerRep != LittleEndian:
    swap(bytes[0], bytes[3])
    swap(bytes[1], bytes[2])
  copyMem(addr result, addr bytes[0], 4)

proc decodeFloat64*(buf: NDRBuffer): float64 =
  buf.align(Align8)
  var bytes = buf.readBytes(8)
  if buf.dataRep.integerRep != LittleEndian:
    for i in 0..<4:
      swap(bytes[i], bytes[7-i])
  copyMem(addr result, addr bytes[0], 8)

proc decodeBool*(buf: NDRBuffer): bool =
  decodeUint8(buf) != 0

# ==================== String Encoding/Decoding ====================

proc encodeConformantString*(buf: NDRBuffer, value: string, isWide: bool = true) =
  ## Encode a conformant string (used in arrays and structures)
  if isWide:
    # Convert to UTF-16LE
    var utf16: seq[uint16] = @[]
    for ch in value:
      utf16.add(ch.uint16)
    utf16.add(0'u16)  # Null terminator
    
    let maxCount = utf16.len.uint32
    let offset = 0'u32
    let actualCount = utf16.len.uint32
    
    # Encode the conformant array header
    encodeUint32(buf, maxCount)
    encodeUint32(buf, offset)
    encodeUint32(buf, actualCount)
    
    # Encode the string data
    for ch in utf16:
      encodeUint16(buf, ch)
  else:
    # ASCII string
    let strWithNull = value & "\0"
    let maxCount = strWithNull.len.uint32
    let offset = 0'u32
    let actualCount = strWithNull.len.uint32
    
    encodeUint32(buf, maxCount)
    encodeUint32(buf, offset)
    encodeUint32(buf, actualCount)
    
    for ch in strWithNull:
      encodeUint8(buf, ch.uint8)

proc encodeUniqueString*(buf: NDRBuffer, value: string, isWide: bool = true) =
  ## Encode a unique pointer to a string
  if value.len == 0:
    # Null pointer
    buf.align(Align4)
    encodeUint32(buf, 0)
  else:
    # Check if we've already encoded this string
    if value in buf.stringReferences:
      buf.align(Align4)
      encodeUint32(buf, buf.stringReferences[value])
    else:
      let refId = buf.getNextReferentId()
      buf.stringReferences[value] = refId
      buf.align(Align4)
      encodeUint32(buf, refId)
      
      # Defer the actual string encoding
      let capturedValue = value
      let capturedIsWide = isWide
      buf.deferPointerEncoding(proc() =
        encodeConformantString(buf, capturedValue, capturedIsWide)
      )

proc decodeConformantString*(buf: NDRBuffer, isWide: bool = true): string =
  let maxCount = decodeUint32(buf)
  let offset = decodeUint32(buf)
  let actualCount = decodeUint32(buf)
  
  if actualCount == 0:
    return ""
  
  if isWide:
    var utf16: seq[uint16] = @[]
    for i in 0..<actualCount:
      utf16.add(decodeUint16(buf))
    
    # Convert UTF-16 to string (excluding null terminator)
    result = ""
    for i in 0..<utf16.len-1:
      if utf16[i] < 128:
        result.add(chr(utf16[i]))
      else:
        # Handle multi-byte UTF-16 properly in production
        result.add('?')
  else:
    for i in 0..<actualCount-1:  # Exclude null terminator
      result.add(chr(decodeUint8(buf)))
    discard decodeUint8(buf)  # Skip null terminator

proc decodeUniqueString*(buf: NDRBuffer, isWide: bool = true): string =
  buf.align(Align4)
  let refId = decodeUint32(buf)
  if refId == 0:
    return ""
  
  # Mark where this pointer's data should be found
  if refId notin buf.pointerValues:
    # This is a forward reference - the data will come later
    # We'll need to decode it in a second pass
    return ""  # Placeholder - will be filled later
  
  # If we've seen this referent ID before, jump to its data
  let savedPos = buf.position
  buf.position = buf.pointerValues[refId]
  result = decodeConformantString(buf, isWide)
  buf.position = savedPos

# New function to handle deferred string decoding
proc decodeUniqueStringDeferred*(buf: NDRBuffer, refId: uint32, isWide: bool = true): string =
  if refId == 0:
    return ""
  
  if refId in buf.pointerValues:
    let savedPos = buf.position
    buf.position = buf.pointerValues[refId]
    result = decodeConformantString(buf, isWide)
    buf.position = savedPos
  else:
    # Data not yet available
    result = ""

# ==================== Pointer Encoding/Decoding ====================

proc encodeUniquePointer*[T](buf: NDRBuffer, value: ptr T, encoder: proc(buf: NDRBuffer, val: T)) =
  ## Encode a unique pointer
  if value.isNil:
    buf.align(Align4)
    encodeUint32(buf, 0)
  else:
    let refId = buf.getNextReferentId()
    buf.align(Align4)
    encodeUint32(buf, refId)
    
    # Defer the actual data encoding
    let capturedValue = value[]
    buf.deferPointerEncoding(proc() =
      encoder(buf, capturedValue)
    )

proc encodeReferencePointer*[T](buf: NDRBuffer, value: T, encoder: proc(buf: NDRBuffer, val: T)) =
  ## Encode a reference pointer (cannot be null)
  let refId = buf.getNextReferentId()
  buf.align(Align4)
  encodeUint32(buf, refId)
  
  # Defer the actual data encoding
  let capturedValue = value
  buf.deferPointerEncoding(proc() =
    encoder(buf, capturedValue)
  )

proc decodeUniquePointer*[T](buf: NDRBuffer, decoder: proc(buf: NDRBuffer): T): ptr T =
  buf.align(Align4)
  let refId = decodeUint32(buf)
  if refId == 0:
    return nil
  
  result = create(T)
  result[] = decoder(buf)

# ==================== Array Encoding/Decoding ====================

proc encodeConformantArray*[T](buf: NDRBuffer, arr: openArray[T], encoder: proc(buf: NDRBuffer, val: T)) =
  ## Encode a conformant array
  encodeUint32(buf, arr.len.uint32)  # Max count
  
  for item in arr:
    encoder(buf, item)

proc encodeVaryingArray*[T](buf: NDRBuffer, arr: openArray[T], encoder: proc(buf: NDRBuffer, val: T)) =
  ## Encode a varying array
  encodeUint32(buf, 0)  # Offset
  encodeUint32(buf, arr.len.uint32)  # Actual count
  
  for item in arr:
    encoder(buf, item)

proc encodeConformantVaryingArray*[T](buf: NDRBuffer, arr: openArray[T], encoder: proc(buf: NDRBuffer, val: T)) =
  ## Encode a conformant varying array
  encodeUint32(buf, arr.len.uint32)  # Max count
  encodeUint32(buf, 0)  # Offset
  encodeUint32(buf, arr.len.uint32)  # Actual count
  
  for item in arr:
    encoder(buf, item)

proc decodeConformantArray*[T](buf: NDRBuffer, decoder: proc(buf: NDRBuffer): T): seq[T] =
  let maxCount = decodeUint32(buf)
  result = @[]
  for i in 0..<maxCount:
    result.add(decoder(buf))

proc decodeVaryingArray*[T](buf: NDRBuffer, maxCount: uint32, decoder: proc(buf: NDRBuffer): T): seq[T] =
  let offset = decodeUint32(buf)
  let actualCount = decodeUint32(buf)
  result = @[]
  for i in 0..<actualCount:
    result.add(decoder(buf))

proc decodeConformantVaryingArray*[T](buf: NDRBuffer, decoder: proc(buf: NDRBuffer): T): seq[T] =
  let maxCount = decodeUint32(buf)
  let offset = decodeUint32(buf)
  let actualCount = decodeUint32(buf)
  result = @[]
  for i in 0..<actualCount:
    result.add(decoder(buf))

# ==================== Structure Support ====================

proc encodeStruct*(buf: NDRBuffer, encoder: proc(buf: NDRBuffer)) =
  ## Encode a structure
  buf.align(Align8)  # Structures are typically 8-byte aligned
  encoder(buf)

proc decodeStruct*(buf: NDRBuffer, decoder: proc(buf: NDRBuffer)) =
  ## Decode a structure
  buf.align(Align8)
  decoder(buf)

# ==================== Union Support ====================

proc encodeUnion*(buf: NDRBuffer, discriminant: uint32, encoder: proc(buf: NDRBuffer)) =
  ## Encode a discriminated union
  buf.align(Align4)
  encodeUint32(buf, discriminant)
  buf.align(Align8)  # Union arms are typically 8-byte aligned
  encoder(buf)

proc decodeUnionDiscriminant*(buf: NDRBuffer): uint32 =
  ## Decode union discriminant
  buf.align(Align4)
  result = decodeUint32(buf)
  buf.align(Align8)  # Prepare for union arm

# ==================== Generic Encode/Decode ====================

proc encode*[T](buf: NDRBuffer, value: T) =
  ## Generic encode function
  when T is uint8:
    encodeUint8(buf, value)
  elif T is uint16:
    encodeUint16(buf, value)
  elif T is uint32:
    encodeUint32(buf, value)
  elif T is uint64:
    encodeUint64(buf, value)
  elif T is int8:
    encodeInt8(buf, value)
  elif T is int16:
    encodeInt16(buf, value)
  elif T is int32:
    encodeInt32(buf, value)
  elif T is int64:
    encodeInt64(buf, value)
  elif T is float32:
    encodeFloat32(buf, value)
  elif T is float64:
    encodeFloat64(buf, value)
  elif T is bool:
    encodeBool(buf, value)
  elif T is string:
    encodeUniqueString(buf, value)
  elif T is enum:
    encodeUint32(buf, value.ord.uint32)
  else:
    {.error: "Unsupported type for generic encode".}

proc decode*[T](buf: NDRBuffer, _: typedesc[T]): T =
  ## Generic decode function
  when T is uint8:
    result = decodeUint8(buf)
  elif T is uint16:
    result = decodeUint16(buf)
  elif T is uint32:
    result = decodeUint32(buf)
  elif T is uint64:
    result = decodeUint64(buf)
  elif T is int8:
    result = decodeInt8(buf)
  elif T is int16:
    result = decodeInt16(buf)
  elif T is int32:
    result = decodeInt32(buf)
  elif T is int64:
    result = decodeInt64(buf)
  elif T is float32:
    result = decodeFloat32(buf)
  elif T is float64:
    result = decodeFloat64(buf)
  elif T is bool:
    result = decodeBool(buf)
  elif T is string:
    result = decodeUniqueString(buf)
  elif T is enum:
    result = T(decodeUint32(buf))
  else:
    {.error: "Unsupported type for generic decode".}

# ==================== Helper Functions ====================

proc toHex*(data: seq[uint8]): string =
  ## Convert byte sequence to hex string
  result = ""
  for i, b in data:
    result.add(b.toHex(2).toLowerAscii())
    if i < data.len - 1:
      result.add(" ")

proc fromHex*(hex: string): seq[uint8] =
  ## Convert hex string to byte sequence
  let cleaned = hex.replace(" ", "").replace("\n", "")
  result = @[]
  var i = 0
  while i < cleaned.len:
    let byteStr = cleaned[i..min(i+1, cleaned.len-1)]
    result.add(parseHexInt(byteStr).uint8)
    i += 2

# ==================== Example RPC Structures ====================

proc encodeUUID*(buf: NDRBuffer, uuid: UUID) =
  encodeUint32(buf, uuid.data1)
  encodeUint16(buf, uuid.data2)
  encodeUint16(buf, uuid.data3)
  for b in uuid.data4:
    encodeUint8(buf, b)

proc decodeUUID*(buf: NDRBuffer): UUID =
  result.data1 = decodeUint32(buf)
  result.data2 = decodeUint16(buf)
  result.data3 = decodeUint16(buf)
  for i in 0..<8:
    result.data4[i] = decodeUint8(buf)

proc encodePDUHeader*(buf: NDRBuffer, header: PDUHeader) =
  encodeUint8(buf, header.version)
  encodeUint8(buf, header.minorVersion)
  encodeUint8(buf, header.pType.uint8)
  encodeUint8(buf, header.pFlags)
  for b in header.drep:
    encodeUint8(buf, b)
  encodeUint16(buf, header.fragLength)
  encodeUint16(buf, header.authLength)
  encodeUint32(buf, header.callId)

proc decodePDUHeader*(buf: NDRBuffer): PDUHeader =
  result.version = decodeUint8(buf)
  result.minorVersion = decodeUint8(buf)
  result.pType = PDUType(decodeUint8(buf))
  result.pFlags = decodeUint8(buf)
  for i in 0..<4:
    result.drep[i] = decodeUint8(buf)
  result.fragLength = decodeUint16(buf)
  result.authLength = decodeUint16(buf)
  result.callId = decodeUint32(buf)
