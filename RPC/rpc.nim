import ../RPC/ndr
import std/[strformat, options, strutils]

# ==================== SRVSVC Protocol Structures ====================

type
  ShareType* = enum
    stDiskTree = 0x00000000
    stPrintQueue = 0x00000001
    stDevice = 0x00000002
    stIPC = 0x00000003
    stClusterFS = 0x02000000
    stClusterSOFS = 0x04000000
    stClusterDFS = 0x08000000
    stSpecial = 0x80000000

  ShareInfo0* = object
    netName*: string

  ShareInfo1* = object
    netName*: string
    shareType*: ShareType
    remark*: string

  ShareInfo2* = object
    netName*: string
    shareType*: ShareType
    remark*: string
    permissions*: uint32
    maxUses*: uint32
    currentUses*: uint32
    path*: string
    password*: string

  ShareInfoContainer0* = object
    entriesRead*: uint32
    buffer*: seq[ShareInfo0]

  ShareInfoContainer1* = object
    entriesRead*: uint32
    buffer*: seq[ShareInfo1]

  ShareInfoContainer2* = object
    entriesRead*: uint32
    buffer*: seq[ShareInfo2]

  ShareInfoLevel* = enum
    silLevel0 = 0
    silLevel1 = 1
    silLevel2 = 2

  ShareEnum* = object
    level*: ShareInfoLevel
    container*: pointer  # Will be cast based on level

# ==================== Encoding Functions ====================

proc encodeShareInfo0*(buf: NDRBuffer, info: ShareInfo0) =
  encodeUniqueString(buf, info.netName)

proc encodeShareInfo1*(buf: NDRBuffer, info: ShareInfo1) =
  encodeUniqueString(buf, info.netName)
  encode(buf, info.shareType)
  encodeUniqueString(buf, info.remark)

proc encodeShareInfo2*(buf: NDRBuffer, info: ShareInfo2) =
  encodeUniqueString(buf, info.netName)
  encode(buf, info.shareType)
  encodeUniqueString(buf, info.remark)
  encode(buf, info.permissions)
  encode(buf, info.maxUses)
  encode(buf, info.currentUses)
  encodeUniqueString(buf, info.path)
  encodeUniqueString(buf, info.password)

proc encodeShareInfoContainer1*(buf: NDRBuffer, container: ShareInfoContainer1) =
  encodeUint32(buf, container.entriesRead)
  
  if container.buffer.len > 0:
    # Encode unique pointer to buffer
    let refId = buf.getNextReferentId()
    encodeUint32(buf, refId)
    
    # Defer array encoding
    let capturedBuffer = container.buffer
    buf.deferPointerEncoding(proc() =
      # Encode conformant array header
      encodeUint32(buf, capturedBuffer.len.uint32)
      
      # Encode each element
      for info in capturedBuffer:
        encodeShareInfo1(buf, info)
    )
  else:
    encodeUint32(buf, 0'u32)  # Null pointer

proc encodeShareEnum*(buf: NDRBuffer, shareEnum: ptr ShareEnum) =
  if shareEnum.isNil:
    encode(buf, 0'u32)
    return
  
  # Encode pointer
  let refId = buf.getNextReferentId()
  encode(buf, refId)
  
  # Defer structure encoding
  let level = shareEnum.level
  let container = shareEnum.container
  
  buf.deferPointerEncoding(proc() =
    # Encode the level
    encode(buf, level)
    
    # Encode union discriminant
    encode(buf, level.ord.uint32)
    
    # Encode the appropriate container based on level
    case level:
    of silLevel0:
      if not container.isNil:
        let c0 = cast[ptr ShareInfoContainer0](container)
        encode(buf, c0.entriesRead)
        # ... encode buffer
    of silLevel1:
      if not container.isNil:
        let c1 = cast[ptr ShareInfoContainer1](container)
        encodeShareInfoContainer1(buf, c1[])
    of silLevel2:
      if not container.isNil:
        let c2 = cast[ptr ShareInfoContainer2](container)
        # ... encode container2
  )

# ==================== NetrShareEnum Function ====================

proc NetrShareEnum*(
  serverName: string,
  infoStruct: ptr ShareEnum,
  prefMaxLen: uint32 = 0xFFFFFFFF'u32,
  totalEntries: ptr uint32 = nil,
  resumeHandle: ptr uint32 = nil
): seq[uint8] =
  ## Encode NetrShareEnum RPC call
  let buf = newNDRBuffer()
  
  # ServerName - unique string
  encodeUniqueString(buf, serverName)
  
  # InfoStruct - encode the share enumeration structure
  encodeShareEnum(buf, infoStruct)
  
  # PreferedMaximumLength
  encode(buf, prefMaxLen)
  
  # TotalEntries - unique pointer
  if totalEntries.isNil:
    encode(buf, 0'u32)
  else:
    let refId = buf.getNextReferentId()
    encode(buf, refId)
    let capturedValue = totalEntries[]
    buf.deferPointerEncoding(proc() =
      encode(buf, capturedValue)
    )
  
  # ResumeHandle - unique pointer
  if resumeHandle.isNil:
    encode(buf, 0'u32)
  else:
    let refId = buf.getNextReferentId()
    encode(buf, refId)
    let capturedValue = resumeHandle[]
    buf.deferPointerEncoding(proc() =
      encode(buf, capturedValue)
    )
  
  # Process all deferred pointers
  buf.processDeferredPointers()
  
  result = buf.data

# ==================== Decoding Functions ====================

proc decodeShareInfo1*(buf: NDRBuffer): ShareInfo1 =
  # Just read the pointer references, don't try to decode strings
  buf.align(Align4)
  let netNameRef = decodeUint32(buf)  # Just read the reference ID
  result.shareType = ShareType(decodeUint32(buf))
  buf.align(Align4) 
  let remarkRef = decodeUint32(buf)  # Just read the reference ID
  
  # Strings will be filled in later when we hit the deferred data section
  result.netName = ""  # Placeholder
  result.remark = ""   # Placeholder

proc decodeShareInfoContainer1*(buf: NDRBuffer): ShareInfoContainer1 =
  result.entriesRead = decode(buf, uint32)
  
  let bufferPtr = decode(buf, uint32)
  if bufferPtr != 0:
    # Decode conformant array
    let count = decode(buf, uint32)
    result.buffer = @[]
    for i in 0..<count:
      result.buffer.add(decodeShareInfo1(buf))

proc decodeNetrShareEnumResponse*(data: seq[uint8]): tuple[
  level: ShareInfoLevel,
  container: ShareInfoContainer1,
  totalEntries: uint32,
  resumeHandle: Option[uint32],
  status: uint32
] =
  ## Decode NetrShareEnum response with proper deferred pointer handling
  let buf = newNDRBuffer()
  buf.data = data
  
  # Decode level
  result.level = ShareInfoLevel(decodeUint32(buf))
  
  # Decode union discriminant
  let discriminant = decodeUint32(buf)
  
  # Decode container based on level
  case result.level:
  of silLevel1:
    # Read entriesRead
    result.container.entriesRead = decodeUint32(buf)
    
    # Read buffer pointer
    buf.align(Align4)
    let bufferPtr = decodeUint32(buf)
    
    # Read totalEntries (comes before deferred data)
    result.totalEntries = decodeUint32(buf)
    
    # Read resumeHandle pointer
    buf.align(Align4)
    let resumePtr = decodeUint32(buf)
    
    # Now we're at the deferred pointer data section
    if bufferPtr != 0:
      # Decode conformant array header
      let count = decodeUint32(buf)
      result.container.buffer = @[]
      
      # Collect all ShareInfo1 structures and their references
      var refs: seq[tuple[netNameRef, remarkRef: uint32]] = @[]
      
      for i in 0..<count:
        buf.align(Align4)
        let netNameRef = decodeUint32(buf)
        let shareTypeValue = decodeUint32(buf)
        let shareType = case shareTypeValue
          of 0x00000000'u32: stDiskTree
          of 0x00000001'u32: stPrintQueue
          of 0x00000002'u32: stDevice
          of 0x00000003'u32: stIPC
          of 0x02000000'u32: stClusterFS
          of 0x04000000'u32: stClusterSOFS
          of 0x08000000'u32: stClusterDFS
          of 0x80000000'u32: stSpecial
          else: stDiskTree  # Default fallback
        buf.align(Align4)
        let remarkRef = decodeUint32(buf)
        
        var info = ShareInfo1()
        info.shareType = shareType
        result.container.buffer.add(info)
        refs.add((netNameRef, remarkRef))
      
      # Now decode the deferred string data IN THE ORDER POINTERS APPEARED
      # This is critical - NDR puts deferred data in encounter order, not grouped by field
      for i in 0..<count:
        if refs[i].netNameRef != 0:
          result.container.buffer[i].netName = decodeConformantString(buf)
        if refs[i].remarkRef != 0:
          result.container.buffer[i].remark = decodeConformantString(buf)
    
    # Decode resume handle if present
    if resumePtr != 0:
      result.resumeHandle = some(decodeUint32(buf))
    
  else:
    raise newException(NDRError, "Unsupported share info level")
  
  # Decode status (NTSTATUS/HRESULT) - this comes at the very end
  result.status = decodeUint32(buf)

# ==================== SAMR Protocol Examples ====================

type
  SamrHandle* = array[20, uint8]
  
  SamrDomainInfo1* = object
    minPasswordLength*: uint16
    passwordHistoryLength*: uint16
    passwordProperties*: uint32
    maxPasswordAge*: int64
    minPasswordAge*: int64

  SamrUserInfo21* = object
    lastLogon*: int64
    lastLogoff*: int64
    passwordLastSet*: int64
    accountExpires*: int64
    passwordCanChange*: int64
    passwordMustChange*: int64
    userName*: string
    fullName*: string
    homeDirectory*: string
    homeDirectoryDrive*: string
    scriptPath*: string
    profilePath*: string
    adminComment*: string
    workstations*: string
    userComment*: string
    parameters*: string
    lmOwfPassword*: array[16, uint8]
    ntOwfPassword*: array[16, uint8]
    privateData*: string
    securityDescriptor*: seq[uint8]
    userId*: uint32
    primaryGroupId*: uint32
    userAccountControl*: uint32
    whichFields*: uint32
    logonHours*: seq[uint8]
    badPasswordCount*: uint16
    logonCount*: uint16
    countryCode*: uint16
    codePage*: uint16
    lmPasswordPresent*: bool
    ntPasswordPresent*: bool
    passwordExpired*: bool

proc encodeSamrHandle*(buf: NDRBuffer, handle: SamrHandle) =
  for b in handle:
    encodeUint8(buf, b)

proc decodeSamrHandle*(buf: NDRBuffer): SamrHandle =
  for i in 0..<20:
    result[i] = decodeUint8(buf)

proc SamrConnect5*(
  serverName: string,
  desiredAccess: uint32,
  inVersion: uint32 = 1,
  inRevisionInfo: uint32 = 3
): seq[uint8] =
  ## Encode SamrConnect5 RPC call
  let buf = newNDRBuffer()
  
  # ServerName
  encodeUniqueString(buf, serverName)
  
  # DesiredAccess
  encode(buf, desiredAccess)
  
  # InVersion
  encode(buf, inVersion)
  
  # InRevisionInfo union
  encode(buf, inVersion)  # Discriminant
  encode(buf, inRevisionInfo)  # Union data
  
  # OutVersion - unique pointer (server will fill)
  encode(buf, 0'u32)
  
  # OutRevisionInfo - unique pointer (server will fill)
  encode(buf, 0'u32)
  
  buf.processDeferredPointers()
  result = buf.data

# ==================== LSA Protocol Examples ====================

type
  LsaHandle* = array[20, uint8]
  
  LsaUnicodeString* = object
    length*: uint16
    maximumLength*: uint16
    buffer*: string

  LsaObjectAttributes* = object
    length*: uint32
    rootDirectory*: LsaHandle
    objectName*: ptr LsaUnicodeString
    attributes*: uint32
    securityDescriptor*: pointer
    securityQualityOfService*: pointer

proc encodeLsaUnicodeString*(buf: NDRBuffer, str: LsaUnicodeString) =
  encode(buf, str.length)
  encode(buf, str.maximumLength)
  encodeUniqueString(buf, str.buffer)

proc encodeLsaObjectAttributes*(buf: NDRBuffer, attrs: LsaObjectAttributes) =
  encode(buf, attrs.length)
  encodeSamrHandle(buf, attrs.rootDirectory)  # Reuse handle encoding
  
  if attrs.objectName.isNil:
    encode(buf, 0'u32)
  else:
    let refId = buf.getNextReferentId()
    encode(buf, refId)
    let capturedValue = attrs.objectName[]
    buf.deferPointerEncoding(proc() =
      encodeLsaUnicodeString(buf, capturedValue)
    )
  
  encode(buf, attrs.attributes)
  encode(buf, 0'u32)  # Null security descriptor
  encode(buf, 0'u32)  # Null QoS

proc LsaOpenPolicy2*(
  systemName: string,
  objectAttributes: LsaObjectAttributes,
  desiredAccess: uint32
): seq[uint8] =
  ## Encode LsaOpenPolicy2 RPC call
  let buf = newNDRBuffer()
  
  # SystemName
  encodeUniqueString(buf, systemName)
  
  # ObjectAttributes
  encodeLsaObjectAttributes(buf, objectAttributes)
  
  # DesiredAccess
  encode(buf, desiredAccess)
  
  buf.processDeferredPointers()
  result = buf.data

# ==================== Test/Example Usage ====================

when isMainModule:
  echo "NDR Library Examples\n"
  echo "=".repeat(50)
  
  # Example 1: NetrShareEnum
  echo "\n1. NetrShareEnum Request:"
  var container1 = ShareInfoContainer1(entriesRead: 0, buffer: @[])
  var shareEnum = ShareEnum(level: silLevel1, container: addr container1)
  var totalEntries: uint32 = 0
  var resumeHandle: uint32 = 0
  
  let shareEnumData = NetrShareEnum(
    "\\\\WIN-SERVER",
    addr shareEnum,
    0xFFFFFFFF'u32,
    addr totalEntries,
    addr resumeHandle
  )
  
  echo fmt"Encoded {shareEnumData.len} bytes:"
  for i in 0..<min(64, shareEnumData.len):
    if i mod 16 == 0:
      echo ""
    stdout.write(fmt"{shareEnumData[i]:02x} ")
  echo "\n..."
  
  # Example 2: SamrConnect5
  echo "\n2. SamrConnect5 Request:"
  let samrConnectData = SamrConnect5(
    "\\\\WIN-DC01",
    0x02000000'u32  # MAXIMUM_ALLOWED
  )
  
  echo fmt"Encoded {samrConnectData.len} bytes:"
  for i in 0..<min(64, samrConnectData.len):
    if i mod 16 == 0:
      echo ""
    stdout.write(fmt"{samrConnectData[i]:02x} ")
  echo "\n..."
  
  # Example 3: LsaOpenPolicy2
  echo "\n3. LsaOpenPolicy2 Request:"
  var objName = LsaUnicodeString(
    length: 0,
    maximumLength: 0,
    buffer: ""
  )
  
  let objAttrs = LsaObjectAttributes(
    length: 24,
    rootDirectory: default(LsaHandle),
    objectName: nil,
    attributes: 0,
    securityDescriptor: nil,
    securityQualityOfService: nil
  )
  
  let lsaOpenData = LsaOpenPolicy2(
    "\\\\WIN-DC01",
    objAttrs,
    0x02000000'u32
  )
  
  echo fmt"Encoded {lsaOpenData.len} bytes:"
  for i in 0..<min(64, lsaOpenData.len):
    if i mod 16 == 0:
      echo ""
    stdout.write(fmt"{lsaOpenData[i]:02x} ")
  echo "\n..."
  
  # Example 4: Decoding
  echo "\n4. Decoding Example:"
  
  # Create a mock response that matches actual NDR wire format
  let mockBuf = newNDRBuffer()
  
  # === Main structure ===
  # Level
  encodeUint32(mockBuf, silLevel1.ord.uint32)
  
  # Union discriminant
  encodeUint32(mockBuf, 1'u32)
  
  # Container entriesRead
  encodeUint32(mockBuf, 2'u32)
  
  # Buffer pointer (non-null)
  encodeUint32(mockBuf, 0x20000'u32)
  
  # TotalEntries
  encodeUint32(mockBuf, 2'u32)
  
  # ResumeHandle pointer (null)
  encodeUint32(mockBuf, 0'u32)
  
  # === Deferred pointer data section ===
  # Conformant array header
  encodeUint32(mockBuf, 2'u32)  # array count
  
  # First ShareInfo1
  mockBuf.align(Align4)
  encodeUint32(mockBuf, 0x20001'u32)  # netName pointer
  encodeUint32(mockBuf, stDiskTree.ord.uint32)  # shareType
  mockBuf.align(Align4)
  encodeUint32(mockBuf, 0x20002'u32)  # remark pointer
  
  # Second ShareInfo1
  mockBuf.align(Align4)
  encodeUint32(mockBuf, 0x20003'u32)  # netName pointer
  encodeUint32(mockBuf, stDiskTree.ord.uint32)  # shareType
  mockBuf.align(Align4)
  encodeUint32(mockBuf, 0x20004'u32)  # remark pointer
  
  # === Deferred string data ===
  # CRITICAL: Deferred data appears in ENCOUNTER ORDER, not grouped by field
  # First struct's strings
  encodeConformantString(mockBuf, "ADMIN$")       # First struct's netName (ref 0x20001)
  encodeConformantString(mockBuf, "Remote Admin")  # First struct's remark (ref 0x20002)
  
  # Second struct's strings  
  encodeConformantString(mockBuf, "C$")            # Second struct's netName (ref 0x20003)
  encodeConformantString(mockBuf, "Default share") # Second struct's remark (ref 0x20004)
  
  # Status at the end
  encodeUint32(mockBuf, 0'u32)  # SUCCESS
  
  # Now decode it
  let decoded = decodeNetrShareEnumResponse(mockBuf.data)
  echo fmt"Decoded level: {decoded.level}"
  echo fmt"Decoded entries: {decoded.container.entriesRead}"
  echo fmt"Total entries: {decoded.totalEntries}"
  echo fmt"Status: 0x{decoded.status:08x}"
  
  if decoded.container.buffer.len > 0:
    echo "Shares found:"
    for share in decoded.container.buffer:
      echo fmt"  - {share.netName} ({share.shareType}): {share.remark}"
  
  echo "\n" & "=".repeat(50)
  echo "Examples complete!"
