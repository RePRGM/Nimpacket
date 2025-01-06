import std/[net, strutils, endians, times, sysrand]
import hashlib/rhash/[md4, md5]

from std/sequtils import concat, mapIt, toSeq

const
  SMB2_MAGIC = [0xFE'u8, 'S'.uint8, 'M'.uint8, 'B'.uint8]
  SMB2_HEADER_SIZE = 64
  SMB2_IOCTL_RESP_HEADER_SIZE = 48  # Size of IOCTL response header
  
  # SMB2 Commands
  SMB2_NEGOTIATE = 0x0000'u16
  SMB2_SESSION_SETUP = 0x0001'u16
  SMB2_TREE_CONNECT = 0x0003'u16
  SMB2_TREE_DISCONNECT = 0x0004'u16
  SMB2_CREATE = 0x0005'u16
  SMB2_CLOSE = 0x0006'u16
  SMB2_READ = 0x0008'u16
  SMB2_WRITE = 0x0009'u16
  SMB2_IOCTL = 0x000B'u16

  # NTLM flags without signing
  NTLM_NEGOTIATE_UNICODE = 0x00000001'u32 # 0x05 bit 0
  NTLM_NEGOTIATE_NTLM = 0x00000200'u32
  NTLM_REQUEST_TARGET = 0x00000004'u32 # 0x08 bit 2
  NTLM_NEGOTIATE_128 = 0x20000000'u32 # 0xA0 bit 7
  NTLM_NEGOTIATE_VERSION = 0x02000000'u32 # 0xA0 bit 5
  NTLM_NEGOTIATE_EXTENDED_SESSIONSECURITY = 0x00080000'u32 # 0x80 bit 7
  NTLM_NEGOTIATE_OEM = 0x00000002'u32 # 0x05 bit 1

  # File Access Rights
  FILE_READ_DATA = 0x00000001'u32
  FILE_WRITE_DATA = 0x00000002'u32
  FILE_READ_EA = 0x00000008'u32
  FILE_WRITE_EA = 0x00000010'u32
  FILE_READ_ATTRIBUTES = 0x00000080'u32
  FILE_WRITE_ATTRIBUTES = 0x00000100'u32
  SYNCHRONIZE = 0x00100000'u32

  # Share Access
  FILE_SHARE_READ = 0x00000001'u32
  FILE_SHARE_WRITE = 0x00000002'u32

type
  AVPairType = enum
    MsvAvEOL = 0
    MsvAvNbComputerName = 1
    MsvAvNbDomainName = 2
    MsvAvDnsComputerName = 3
    MsvAvDnsDomainName = 4
    MsvAvDnsTreeName = 5
    MsvAvFlags = 6
    MsvAvTimestamp = 7
    MsvAvSingleHost = 8
    MsvAvTargetName = 9
    MsvAvChannelBindings = 10

  AVPair = object
   avId: uint16
   avLen: uint16
   avValue: seq[uint8]

  SMB2Header = object
    protocol: array[4, uint8]
    structureSize: uint16
    creditCharge: uint16
    status: uint32
    command: uint16
    credits: uint16
    flags: uint32
    nextCommand: uint32
    messageId: uint64
    processId: uint32
    treeId: uint32
    sessionId: uint64
    signature: array[16, uint8]
  
  SMB2SESSION_SETUP_REQUEST = object
    structureSize: uint16
    flags: uint8
    securityMode: uint8
    capabilities: uint32
    channel: uint32
    securityBufferOffset: uint16
    securityBufferLength: uint16
    previousSessionId: uint64
  
  SMB2NegotiateRequest = object
    structureSize: uint16
    dialectCount: uint16
    securityMode: uint16
    reserved: uint16
    capabilities: uint32
    clientGUID: array[16, uint8]
    clientStartTime: uint64
    # dialects (variable), padding (variable; optional), negotiateContextList (variable; SMB 3.1.1 only)
  
  SMB2CreateRequest = object
    structureSize: uint16
    securityFlags: uint8
    requestedOplockLevel: uint8
    impersonationLevel: uint32
    smbCreateFlags: uint64
    reserved: uint64
    desiredAccess: uint32
    fileAttributes: uint32
    shareAccess: uint32
    createDisposition: uint32
    createOptions: uint32
    nameOffset: uint16
    nameLength: uint16
    createContextsOffset: uint32
    createContextsLength: uint32

  SMB2WriteRequest = object
    structureSize: uint16
    dataOffset: uint16
    length: uint32
    offset: uint64
    fileID: array[16, uint8]
    channel: uint32
    remainingBytes: uint32
    writeChannelInfoOffset: uint16
    writeChannelInfoLength: uint16
    flags: uint32

  SMB2ReadRequest = object
    structureSize: uint16
    padding: uint8
    flags: uint8
    length: uint32
    offset: uint64
    fileID: array[16, uint8]
    minimumCount: uint32
    channel: uint32
    remainingBytes: uint32
    readChannelInfoOffset: uint16
    readChannelInfoLength: uint16

  SMB2IoctlRequest = object
    structureSize: uint16
    reserved: uint16
    ctlCode: uint32
    fileID: array[16, uint8]
    inputOffset: uint32
    inputCount: uint32
    maxInputResponse: uint32
    outputOffset: uint32
    outputCount: uint32
    maxOutputResponse: uint32
    flags: uint32
    reserved2: uint32
  
  absSyntaxID = object
    ifUUID: array[16, uint8]
    ifVersion: uint16
    ifMinorVersion: uint16

  presContextElement = object
    contextID: uint16
    numTransSyntaxes: uint8
    padding: uint8
    absSyntax: absSyntaxID
    transSyntax: absSyntaxID

  PDUHeader = object
    version: uint8
    minorVersion: uint8
    pType: uint8
    pFlags: uint8
    dRep: array[4, uint8]
    fragLength: uint16
    authLength: uint16
    callID: uint32

  PDUBind = object
    header: PDUHeader
    maxXmitFrag: uint16
    maxRecvFrag: uint16
    assocGroupID: uint32
    numContextElements: uint8

  PDURequest = object
    header: PDUHeader
    allocHint: uint32
    contextID: uint16
    opNum: uint16
  
  PacketType* = enum
    ptRequest
    ptResponse

  Share* = object
    name*: string
    description*: string

  NTLMNegoMsg = object
    messageType: uint32
    flags: uint32
    domainNameLength: uint16
    domainNameMaxLen: uint16
    domainNameOffset: uint32
    workstationNameLength: uint16
    workstationNameMaxLen: uint16
    workstationNameOffset: uint32
    majorVersionNumber: uint8
    minorVersionNumber: uint8
    buildNumber: uint16
    reserved: array[3, uint8]
    revision: uint8
  
  NTLMAuthMsg = object
    signature: array[8, uint8]
    messageType: uint32
    lmChallengeResponseLen: uint16
    lmChallengeResponseMaxLen: uint16
    lmChallengeResponseBufferOffset: uint32
    ntChallengeResponseLen: uint16
    ntChallengeResponseMaxLen: uint16
    ntChallengeResponseBufferOffset: uint32
    domainNameLen: uint16
    domainNameMaxLen: uint16
    domainNameBufferOffset: uint32
    userNameLen: uint16
    userNameMaxLen: uint16
    userNameBufferOffset: uint32
    workstationLen: uint16
    workstationMaxLen: uint16
    workstationBufferOffset: uint32
    encryptedRandomSessionKeyLen: uint16
    encryptedRandomSessionKeyMaxLen: uint16
    encryptedRandomSessionKeyBufferOffset: uint32
    flags: uint32
    majorVersionNumber: uint8
    minorVersionNumber: uint8
    buildNumber: uint16
    reserved: array[3, uint8]
    revision: uint8
    mic: array[16, uint8]
  
  NTLMv2RESPONSE = object
    response: array[16, uint8]
    ntlmv2ClientChallenge: seq[uint8]

  TreeConnectRequest = object
    structureSize: uint16
    flags: uint16
    pathOffset: uint16
    pathLength: uint16

  NtlmState = object
    username: string
    domain: string
    ntlmHash: string
    negotiateFlags: uint32

  SmbClient = ref object
    socket: Socket
    host: string
    port: Port
    connected: bool
    sessionId: uint64
    treeId: uint32
    messageId: uint64
    ntlmState: NtlmState

proc toUtf16LE(s: string): seq[uint8] =
  result = newSeq[uint8](s.len * 2)
  var j = 0
  for i in 0 ..< s.len:
    result[j] = uint8(s[i])
    result[j + 1] = 0
    j += 2

proc dumpHex(data: openArray[byte], prefix: string = "") =
  for b in data:
    stdout.write(b.toHex(2))
  stdout.write("\n")

proc dumpHexString(data: string, length: int, prefix: string = "") =
  for i in 0..<length:
    stdout.write(cast[byte](data[i]).toHex(2))
  stdout.write("\n")

proc packSMB2Header(header: SMB2Header): seq[uint8] =
  result = newSeq[uint8](64)
  copyMem(result[0].addr, header.protocol[0].addr, 4)
  littleEndian16(result[4].addr, header.structureSize.addr)
  littleEndian16(result[6].addr, header.creditCharge.addr)
  littleEndian32(result[8].addr, header.status.addr)
  littleEndian16(result[12].addr, header.command.addr)
  littleEndian16(result[14].addr, header.credits.addr)
  littleEndian32(result[16].addr, header.flags.addr)
  littleEndian32(result[20].addr, header.nextCommand.addr)
  littleEndian64(result[24].addr, header.messageId.addr)
  littleEndian32(result[32].addr, header.processId.addr)
  littleEndian32(result[36].addr, header.treeId.addr)
  littleEndian64(result[40].addr, header.sessionId.addr)
  copyMem(result[48].addr, header.signature[0].addr, 16)

proc newSmbClient*(host: string, port: int = 445): SmbClient =
  new(result)
  result.socket = newSocket()
  result.host = host
  result.port = Port(port)
  result.connected = false
  result.sessionId = 0
  result.treeId = 0
  result.messageId = 0

proc generateNTLMHash(password: string): string =
  # Convert password to UTF-16LE
  let utf16password = toUtf16LE(password)
  
  # Use the stream API for MD4
  var ctx = init[RHASH_MD4]()
  ctx.update(utf16password)
  let hash = ctx.final()
  
  # Convert to uppercase hex string
  result = ($hash).toUpperAscii()

proc disconnect(client: SmbClient) =
  if client.connected:
    client.socket.close()
    client.connected = false
    client.sessionId = 0
    client.treeId = 0

proc sendNetbiosHeader(client: SmbClient, length: uint32) =
  var header: array[4, uint8]
  header[0] = 0
  header[3] = uint8(length and 0xFF)         # Low byte
  header[2] = uint8((length shr 8) and 0xFF) # Middle byte
  header[1] = uint8((length shr 16) and 0xFF) # High byte
  
  #[
  stdout.write("Sending NetBIOS Header: ")
  for headerByte in header: stdout.write(toHex(headerByte,2))
  echo "\n"
  ]#

  discard client.socket.send(header[0].addr, 4)

proc parseNTLMChallengeMsg(securityBlob: seq[uint8]): tuple[serverChallenge: array[8, uint8], targetName: seq[uint8], targetInfo: seq[uint8]] =
 # Navigate through SPNEGO wrapping to find NTLM message
 var pos = 0
 var ntlmSSPSigStartPos = 0

 while pos < securityBlob.len:
   if pos + 7 < securityBlob.len and
      securityBlob[pos] == 0x4E and    # 'N'
      securityBlob[pos+1] == 0x54 and  # 'T'
      securityBlob[pos+2] == 0x4C and  # 'L'
      securityBlob[pos+3] == 0x4D and  # 'M'
      securityBlob[pos+4] == 0x53 and  # 'S'
      securityBlob[pos+5] == 0x53 and  # 'S'
      securityBlob[pos+6] == 0x50 and  # 'P'
      securityBlob[pos+7] == 0x00:     # '\0'
     
     # Found NTLM message start
     let ntlmStartPos = pos
     pos += 8
     ntlmSSPSigStartPos = pos-8

     # Verify message type is 2 (Challenge)
     let messageType = cast[uint32]([securityBlob[pos], securityBlob[pos+1], 
                                   securityBlob[pos+2], securityBlob[pos+3]])
     if messageType != 2:
       raise newException(IOError, "[-] Message is Not an NTLM Challenge")
     pos += 4

     # Get target name length and offset
     let targetNameLen = cast[uint16]([securityBlob[pos], securityBlob[pos+1]])
     let targetNameOffset = cast[uint32]([securityBlob[pos+4], securityBlob[pos+5],
                                        securityBlob[pos+6], securityBlob[pos+7]])
     pos += 8

     # Get negotiate flags
     let negotiateFlags = cast[uint32]([securityBlob[pos], securityBlob[pos+1],
                                      securityBlob[pos+2], securityBlob[pos+3]])
     pos += 4

     # Get server challenge
     var serverChallenge: array[8, uint8]
     copyMem(addr serverChallenge[0], addr securityBlob[pos], 8)
     pos += 8

     # Skip reserved
     pos += 8

     # Get target info length and offset
     let targetInfoLen = cast[uint16]([securityBlob[pos], securityBlob[pos+1]])
     let targetInfoOffset = cast[uint32]([securityBlob[pos+4], securityBlob[pos+5],
                                        securityBlob[pos+6], securityBlob[pos+7]])
     # Extract Target Info
     var targetInfo = newSeq[uint8](targetInfoLen)
     copyMem(addr targetInfo[0], addr securityBlob[ntlmStartPos.uint32 + targetInfoOffset], targetInfoLen)

     # Extract target name
     var targetName = ""
     var nameBytes: seq[uint8]
     if targetNameLen > 0:
       let startPos = ntlmSSPSigStartPos.uint32 + targetNameOffset
       nameBytes = securityBlob[startPos ..< startPos+targetNameLen]
       targetName = cast[string](nameBytes)

     return (serverChallenge, nameBytes, targetInfo)

   inc pos

 raise newException(IOError, "[-] NTLM Message Not Found in Security Blob")

proc parseSessionSetupResponse(response: seq[uint8]): tuple[status: uint32, sessID: uint64, securityBlob: seq[uint8]] =
  # First check SMB2 header status at offset 8
  let status = cast[uint32]([response[8], response[9], response[10], response[11]])
  
  if status != 0xC0000016.uint32:  # STATUS_MORE_PROCESSING_REQUIRED
    return (status, 0'u64, @[])

  # SMB2 header is 64 bytes
  var pos = 64
  # Get Session ID
  let sessID = cast[uint64]([response[40], response[41], response[42], response[43], response[44], response[45], response[46], response[47]])
  # Get structure size (should be 9)
  let structSize = cast[uint16]([response[pos], response[pos+1]])
  pos += 2

  # Get session flags
  let sessionFlags = cast[uint16]([response[pos], response[pos+1]])
  pos += 2

  # Get security buffer offset and size
  let securityBufferOffset = cast[uint16]([response[pos], response[pos+1]])
  pos += 2
  let securityBufferLength = cast[uint16]([response[pos], response[pos+1]])
  
  # Extract security blob starting at security buffer offset
  let securityBlob = response[securityBufferOffset..<securityBufferOffset+securityBufferLength]
  
  return (status, sessID, securityBlob)

proc recvSMB2Message(client: SmbClient): seq[uint8] =
  # Read NetBios header (4 bytes)
  var header: array[4, uint8]
  let headerRead = client.socket.recv(header[0].addr, 4)
  if headerRead != 4:
    echo "[-] Failed to Read NetBIOS Header. Received ", headerRead, " Bytes!"
    return @[]
    
  # Reconstruct length from 3 bytes
  let payloadLength = uint32(cast[uint8](header[3])) or
                   (uint32(cast[uint8](header[2])) shl 8) or
                   (uint32(cast[uint8](header[1])) shl 16)
  
  #[
  echo "Received NetBIOS header, payload length: ", payloadLength
  stdout.write("Header bytes: ")
  for i in countup(0, 3): stdout.write(cast[byte](header[i]).toHex(2))
  stdout.write("\n")
  ]#

  var payload = newString(payloadLength)
  let payloadRead = client.socket.recv(payload, payloadLength.int)
  if payloadRead != payloadLength.int:
    echo "[-] Failed to Read Complete Payload! Got ", payloadRead, " of ", payloadLength, " Bytes"
    return @[]
  
  #[
  echo "Received payload of ", payloadRead, " bytes"
  stdout.write("Payload: ")
  for i in 0 ..< payloadRead: stdout.write(cast[byte](payload[i]).toHex(2))
  stdout.write("\n")
  ]#

  result = cast[seq[uint8]](payload)

proc sendSMB2Negotiate(client: SmbClient): bool =
  var header = SMB2Header(
    protocol: [0xFE, 0x53, 0x4D, 0x42],
    structureSize: 64,
    creditCharge: 0,             # SMB 2.0.2, must be set to 0
    status: 0, # SMB 2.0.2 and 2.1, must be set to 0
    command: SMB2_NEGOTIATE,
    credits: 1,
    flags: 0,
    nextCommand: 0,
    messageId: 0,
    processId: 0xFEFF,                # Changed from 0xFEFF to 0
    treeId: 0,
    sessionId: 0,
    signature: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
  )

  var smb2NegoReq = SMB2NegotiateRequest(
    structureSize: 36,
    dialectCount: 1,
    securityMode: 1,
    reserved: 0,
    capabilities: 0,
    clientGUID: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    clientStartTime: 0
  )

  var 
    tmp: array[2, uint8]
    smbPayload = packSMB2Header(header)
  
  var negoReq = newSeqUninit[uint8](36)
  copyMem(negoReq[0].addr, smb2NegoReq.addr, sizeof(smb2NegoReq)-1)
  smbPayload.add(negoReq)
  
  # SMB 2.0.2 dialect
  var dialects = [0x0202]
  littleEndian16(tmp[0].addr, dialects[0].addr)
  smbPayload.add(tmp)
  
  #[
  echo "Sending negotiate packet of size: ", smbPayload.len
  stdout.write("Negotiate packet: ")
  for b in smbPayload:
    stdout.write(b.toHex(2))
  stdout.write("\n")
  ]#

  client.sendNetbiosHeader(smbPayload.len.uint32)
  client.socket.send(cast[string](smbPayload))

  # Receive negotiate response
  let response = client.recvSMB2Message()
  
  return response.len > 0

proc createSpnegoToken(ntlmMsg: seq[uint8], msgType: int): seq[uint8] =
  if msgType == 1:
    let 
      ntlmLength = ntlmMsg.len
      totalLength = 40 + ntlmLength # 2 Bytes (0x60 & len) + 8 Bytes (SPNEGO OID) + 10 Bytes (Inner Context Token Headers) + 10 Bytes (Mech Types Structures) + 10 Bytes (NTLMSSP OID) + 8 Bytes (NTLMSSP Signature) + ntlmMsg.len
      innerContextLen = totalLength - 10 # 2 Bytes (0x60 & len) + 2 Bytes (0x06 & len) + 6 Bytes (SPNEGO OID)
      seqLen = innerContextLen - 2 # 2 Bytes (0xa0 & len)
      mechTokenLen = ntlmLength + 10 # 2 Bytes (0xa2 & len) + 8 Bytes (NTLMSSP Signature)
    
    var token = @[0x60'u8, totalLength.uint8]
    token.add([0x06'u8, 0x06, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02]) # 1 Byte (ThisMechId), 1 Byte (ThisMechId Length), 6 Bytes (SPNEGO OID)
    token.add([0xa0'u8, innerContextLen.uint8, 0x30, seqLen.uint8])
    token.add([0xa0'u8, 0x0e, 0x30, 0x0c, 0x06, 0x0a])
    token.add([0x2b'u8, 0x06, 0x01, 0x04, 0x01, 0x82]) # NTLM SSP OID
    token.add([0x37'u8, 0x02, 0x02, 0x0a])
    token.add([0xa2'u8, mechTokenLen.uint8])
    token.add([0x04'u8, (ntlmLength+8).uint8])
    
    token.add([0x4E'u8, 0x54, 0x4C, 0x4D, 0x53, 0x53, 0x50, 0x00]) # NTLM SSP Signature
    token.add(ntlmMsg)

    return token
  elif msgType == 3:
    let 
        ntlmLength = ntlmMsg.len    # NTLM Type 3 message length
        octetStringLength = ntlmLength
        tokenLength = octetStringLength + 4
        sequenceLength = tokenLength + 4
        totalLength = sequenceLength + 4

    var token = @[
    0xa1'u8, 0x82,                                    # NegTokenResp, long form
    uint8(totalLength div 256), uint8(totalLength mod 256),       # Total length bytes
    0x30'u8, 0x82,                                    # Sequence, long form
    uint8(sequenceLength div 256), uint8(sequenceLength mod 256), # Sequence length bytes
    0xa2'u8, 0x82,                                    # Token, long form
    uint8(tokenLength div 256), uint8(tokenLength mod 256),       # Token length bytes
    0x04'u8, 0x82,                                    # Octet string, long form
    uint8(octetStringLength div 256), uint8(octetStringLength mod 256)  # String length bytes
    ]
    token.add(ntlmMsg)
    return token
  return @[]

proc parseTargetInfo(targetInfo: seq[uint8]): seq[AVPair] =
 var pos = 0
 while pos < targetInfo.len:
   var pair: AVPair
   
   # Get type and length
   pair.avId = cast[uint16]([targetInfo[pos], targetInfo[pos+1]])
   pair.avLen = cast[uint16]([targetInfo[pos+2], targetInfo[pos+3]])
   pos += 4

   if pair.avId == MsvAvEOL.uint16: return result

   # Get value
   pair.avValue = newSeq[uint8](pair.avLen)
   for i in 0.uint16 ..< pair.avLen:
     pair.avValue[i] = targetInfo[pos.uint16 + i]
   pos += pair.avLen.int

   result.add(pair)

proc createClientChallenge(avPairs: seq[AVPair], timestamp: uint64): seq[uint8] =
 result = @[
   0x01'u8, 0x01,                      # Resp header
   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, # Reserved
 ]
 
 # Add timestamp
 var timestampBytes: array[8, uint8]
 #littleEndian64(addr timestampBytes[0], addr timestamp)
 copyMem(timestampBytes[0].addr, timestamp.addr, sizeof(timestamp))
 result.add(timestampBytes)
 
 # Add client nonce (8 random bytes)
 result.add(urandom(8))

 # Add zeros for unknown1
 result.add([0x00'u8, 0x00, 0x00, 0x00])

 # Add all AV_PAIRs
 for pair in avPairs:
   var tmp: array[2, uint8]
   # Add type
   littleEndian16(tmp[0].addr, pair.avId.addr)
   result.add(tmp)

   # Add length
   littleEndian16(tmp[0].addr, pair.avLen.addr)
   result.add(tmp)

   # Add value
   result.add(pair.avValue)

 # Add MsvAvEOL
 result.add([0x00'u8, 0x00, 0x00, 0x00])

proc calculateNTLMv2Response(ntlmHash: string, username: string, targetName: string, serverChallenge: array[8, uint8], targetInfo: seq[uint8]): NTLMv2RESPONSE =
    var utf16LEUsername = toUtf16LE(username.toUpperAscii)
    var userTargetConcatenation = newStringUninit(utf16LEUsername.len + targetName.len)
    copyMem(userTargetConcatenation[0].addr, utf16LEUsername[0].addr, utf16LEUsername.len)
    copyMem(userTargetConcatenation[utf16LEUsername.high+1].addr, targetName[0].addr, targetName.len)
    
    var hashBytes = newSeq[uint8](16)
    for i in 0 ..< 16:
        hashBytes[i] = uint8(parseHexInt(ntlmHash[i*2..i*2+1]))

    # Create NTLMv2 Hash
    var hmac = init[Hmac[RHASH_MD5]](hashBytes)
    hmac.update(userTargetConcatenation)
    let ntlmv2Hash = hmac.final().data

    let avPairs = parseTargetInfo(targetInfo)
    # Create temp with server challenge and client blob
    let timestamp = cast[uint64](getTime().toWinTime)
    let clientChallenge = createClientChallenge(avPairs, timestamp)

    var temp = @serverChallenge
    temp.add(clientChallenge)
    
    # Calculate proof
    var hmacProof = init[Hmac[RHASH_MD5]](ntlmv2Hash)
    hmacProof.update(temp)
    
    let ntProof = hmacProof.final().data
    copyMem(result.response[0].addr, ntProof[0].addr, 16)
    result.ntlmv2ClientChallenge = clientChallenge

proc createNTLMMsg(msgType: int, pNTLMStateNegoFlags: ptr uint32 = nil, username: string = "", targetName: seq[uint8] = @[], ntlmv2Resp: NTLMv2RESPONSE = NTLMv2RESPONSE()): seq[uint8] =
  if msgType == 1:
    var negoMsg = NTLMNegoMsg(
        messageType: 1,
        flags: pNTLMStateNegoFlags[],
        domainNameLength: 0,
        domainNameMaxLen: 0,
        domainNameOffset: 0,
        workstationNameLength: 0,
        workstationNameMaxLen: 0,
        workstationNameOffset: 0,
        majorVersionNumber: 6,
        minorVersionNumber: 1,
        buildNumber: 7600,
        reserved: [0'u8, 0, 0],
        revision: 15
    )

    # Create NTLM Negotiate Message
    #echo "\nCrafting NTLM Negotiate Message"
    var ntlmMsg = newSeqUninit[uint8](sizeof(negoMsg))
    copyMem(ntlmMsg[0].addr, negoMsg.addr, sizeof(negoMsg))

    return ntlmMsg
  elif msgType == 3:
    let utf16Usr = toUtf16LE(username)
    let wkstn = toUtf16LE("WKSTN1")
    #echo "\nCrafting NTLM Authenticate Message!"
    # Fixed header size:
    # - NTLMSSP signature (8 bytes)
    # - Message type (4 bytes)
    # - 6 security buffer fields (6 * 8 = 48 bytes)
    # - Flags (4 bytes)
    # - Version (8 bytes)
    # - MIC (16 bytes)
    let fixedHeaderSize = 8 + 4 + 48 + 4 + 8 + 16
    var ntlmAuth = NTLMAuthMsg(
        signature: [0x4e'u8, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00],
        messageType: 3,
        lmChallengeResponseLen: 24,
        lmChallengeResponseMaxLen: 24,
        lmChallengeResponseBufferOffset: fixedHeaderSize.uint32,
        ntChallengeResponseLen: (ntlmv2Resp.response.len + ntlmv2Resp.ntlmv2ClientChallenge.len).uint16,
        ntChallengeResponseMaxLen: (ntlmv2Resp.response.len + ntlmv2Resp.ntlmv2ClientChallenge.len).uint16,
        ntChallengeResponseBufferOffset: (fixedHeaderSize + 24).uint32,
        domainNameLen: (targetName.len).uint16,
        domainNameMaxLen: (targetName.len).uint16,
        domainNameBufferOffset: (fixedHeaderSize + 24 + 16 + ntlmv2Resp.ntlmv2ClientChallenge.len).uint16,
        userNameLen: (utf16Usr.len).uint16,
        userNameMaxLen: (utf16Usr.len).uint16,
        userNameBufferOffset: (fixedHeaderSize + 24 + 16 + ntlmv2Resp.ntlmv2ClientChallenge.len + targetName.len).uint16,
        workstationLen: 0, #wkstn.len.uint16,
        workstationMaxLen: 0, #wkstn.len.uint16,
        workstationBufferOffset: (fixedHeaderSize + 24 + 16 + ntlmv2Resp.ntlmv2ClientChallenge.len + targetName.len + utf16Usr.len).uint16,
        encryptedRandomSessionKeyLen: 0,
        encryptedRandomSessionKeyMaxLen: 0,
        encryptedRandomSessionKeyBufferOffset: (fixedHeaderSize + 24 + 16 + ntlmv2Resp.ntlmv2ClientChallenge.len + targetName.len + utf16Usr.len + 8).uint16,
        flags: pNTLMStateNegoFlags[],
        majorVersionNumber: 6,
        minorVersionNumber: 1,
        buildNumber: 7600,
        reserved: [0'u8, 0, 0],
        revision: 15,
        mic: [0'u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    )
    var ntlmMsg = newSeqUninit[uint8](sizeof(ntlmAuth))
    copyMem(ntlmMsg[0].addr, ntlmAuth.addr, sizeof(ntlmAuth))

    ntlmMsg.add([0'u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]) # LM Response
    ntlmMsg.add(ntlmv2Resp.response)
    ntlmMsg.add(ntlmv2Resp.ntlmv2ClientChallenge)
    ntlmMsg.add(@targetName)
    ntlmMsg.add(utf16Usr)
    #ntlmMsg.add(wkstn)
    # Add Workstation here if it seems to be needed
    return ntlmMsg

  return @[]

proc sendSMB2SessionSetup(client: SmbClient, token: seq[uint8]): seq[uint8] =
  var header = SMB2Header(
    protocol: [0xFE'u8, 0x53, 0x4D, 0x42],
    structureSize: 64,
    creditCharge: 0,
    command: SMB2_SESSION_SETUP,
    credits: 1,
    flags: 0,
    nextCommand: 0,
    messageId: client.messageId,
    processId: 0xFEFF,
    treeId: 0,
    sessionId: client.sessionID,
    signature: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
  )
  inc client.messageId
  
  var sessSetupReq = SMB2SESSION_SETUP_REQUEST(
    structureSize: 25,
    flags: 0,
    securityMode: 1,
    capabilities: 0,
    channel: 0,
    securityBufferOffset: 88,
    securityBufferLength: token.len.uint16,
    previousSessionId: 0
  )

  # Build SMB payload
  # Add SMB2 Header
  var smbPayload = newSeqUninit[uint8](sizeof(header))
  copyMem(smbPayload[0].addr, header.addr, sizeof(header))

  # Add SESSION_SETUP_REQUEST structure
  var sessSetupReqBytes = newSeqUninit[uint8](sizeof(sessSetupReq))
  copyMem(sessSetupReqBytes[0].addr, sessSetupReq.addr, sizeof(sessSetupReq))
  smbPayload = smbPayload.concat(sessSetupReqBytes)
  
  smbPayload.add(token)

  #[
  echo "Sending session setup packet of size: ", smbPayload.len
  stdout.write("Session setup packet: ")
  for b in smbPayload:
    stdout.write(b.toHex(2))
  stdout.write("\n")
  ]#

  client.sendNetbiosHeader(smbPayload.len.uint32)
  client.socket.send(cast[string](smbPayload))

  return client.recvSMB2Message()

proc sessionSetup(client: SmbClient, username: string, ntlmHash: string): bool =
  # Initial Session Setup Request - NTLM Negotiate Message
  let spnegoToken = createSpnegoToken(createNTLMMsg(1, client.ntlmState.negotiateFlags.addr), 1)

  #[
  stdout.write("NTLM Negotiate Message: ")
  for ntlmMsgByte in spnegoToken: stdout.write(toHex(ntlmMsgByte, 2))
  echo "\n"
  ]#

  let negoResponse = client.sendSMB2SessionSetup(spnegoToken)

  # Parse response for NTLM Challenge
  let (status, sessionID, securityBlob) = parseSessionSetupResponse(negoResponse)
  #echo "Status: ", toHex(status)

  client.sessionId = sessionID

  if status == 0xC0000016.uint32: 
    let (serverChallenge, targetName, targetInfo) = parseNTLMChallengeMsg(securityBlob)
    #[
    echo "\nTarget Name: ", cast[string](targetName)
    stdout.write("Server Challenge: ")
    for bytes in serverChallenge: stdout.write(toHex(bytes, 2))
    echo "\n"
    ]#

    # Secondary Session Setup Request - NTLM Auth Message
    # Calculate NTLMv2 Response
    let ntlmv2Response = calculateNTLMv2Response(ntlmHash, username, cast[string](targetName), serverChallenge, targetInfo)

    # Create and send Type 3 message
    let authTkn = createSpnegoToken(createNTLMMsg(3, client.ntlmState.negotiateFlags.addr, username, targetName, ntlmv2Response), 3)
    
    #[
    stdout.write("NTLM Authenticate Message: ")
    for authTknByte in authTkn: stdout.write(toHex(authTknByte, 2))
    echo "\n"
    ]#

    let authResponse = client.sendSMB2SessionSetup(authTkn)
    
    let (authStatus, _, _) = parseSessionSetupResponse(authResponse)
    return authStatus == 0 
  else: return false

proc parseTreeConnectResponse(response: seq[uint8]): tuple[status: uint32, treeId: uint32] =
 # Parse status from SMB header (bytes 8-11 in LE)
 let status = cast[uint32]([response[8], response[9], response[10], response[11]])
 
 if status == 0:  # Success
   # Tree ID is at offset 36-39 in LE
   let treeId = cast[uint32]([response[36], response[37], response[38], response[39]])
   result = (status: status, treeId: treeId)
 else:
   result = (status: status, treeId: 0)

proc connect*(client: SmbClient, username = "", password = "", ntlmHash = "") =
  if not client.connected:
    echo "[*] Connecting to: ", client.host, ":", client.port
    client.socket.connect(client.host, client.port)
    client.socket.setSockOpt(OptKeepAlive, true)
    client.connected = true
    echo "[+] Successfully Connected to Socket"

    # Send Negotiate Protocol Request
    client.messageId = 1
    if not client.sendSMB2Negotiate():
      client.disconnect()
      raise newException(IOError, "SMB2 negotiate failed")

    let actualNtlmHash = if ntlmHash != "": ntlmHash else: generateNTLMHash(password)
    echo "\n[*] NTLM Hash: ", actualNtlmHash

    client.ntlmState = NtlmState(
      username: username,
      domain: "",
      ntlmHash: actualNtlmHash,
      negotiateFlags: NTLM_NEGOTIATE_UNICODE or NTLM_NEGOTIATE_NTLM or NTLM_NEGOTIATE_VERSION or NTLM_REQUEST_TARGET or NTLM_NEGOTIATE_OEM
    )

    if not client.sessionSetup(username, actualNtlmHash):
      client.disconnect()
      raise newException(IOError, "SMB2 session setup failed")

    echo "\n[+] Successfully Authenticated as: ", client.ntlmState.username

proc connectToShare*(client: SmbClient, share: string): void =
  if not client.connected:
    raise newException(IOError, "[-] Not Connected to Server")
  
  var header = SMB2Header(
    protocol: SMB2_MAGIC,
    structureSize: 64,
    creditCharge: 1,
    command: SMB2_TREE_CONNECT,
    credits: 1,
    flags: 0,
    nextCommand: 0,
    messageId: client.messageId,
    processId: 0xFEFF,
    treeId: 0,
    sessionId: client.sessionId,
    signature: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
  )

  inc client.messageId

  var connectData = packSMB2Header(header)
  
  let sharePath = toUtf16LE("\\\\" & client.host & "\\" & share)
  
  var treeConnectReq = TreeConnectRequest(
    structureSize: 9,
    flags: 0, # If not SMB 3.1.1, must be 0
    pathOffset: 72,
    pathLength: sharePath.len.uint16
  )
  
  var treeConnectReqBytes = newSeqUninit[uint8](sizeof(treeConnectReq))
  copyMem(treeConnectReqBytes[0].addr, treeConnectReq.addr, sizeof(treeConnectReq))
  connectData.add(treeConnectReqBytes)
  connectData.add(sharePath)
  
  client.sendNetbiosHeader(connectData.len.uint32)
  client.socket.send(cast[string](connectData))

  let response = client.recvSMB2Message()
  if response.len == 0:
    raise newException(IOError, "[-] Failed to Receive Tree Connect Response")

  let (status, treeId) = parseTreeConnectResponse(response)
  if status != 0:
   client.disconnect()
   raise newException(IOError, "[-] Tree Connect Failed with Status: 0x" & $status)

  client.treeId = treeId

proc openNamedPipe(client: SmbClient, pipeName: string): tuple[persistent, volatile: uint64] =
  var header = SMB2Header(
    protocol: SMB2_MAGIC,
    structureSize: 64,
    creditCharge: 1,
    command: SMB2_CREATE,
    credits: 1,
    flags: 0, 
    nextCommand: 0,
    messageId: client.messageId,
    processId: 0xFEFF,
    treeId: client.treeId,
    sessionId: client.sessionId,
    signature: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
  )
  inc client.messageId

  var createData = packSMB2Header(header)

  # Create Request structure
  var createReq = SMB2CreateRequest(
    structureSize: 57,
    securityFlags: 0,
    requestedOplockLevel: 0,
    impersonationLevel: 2,
    smbCreateFlags: 0,
    reserved: 0,
    desiredAccess: 0x0012019F,
    fileAttributes: 0,
    shareAccess: 7,
    createDisposition: 1,
    createOptions: 0,
    nameOffset: 120,
    createContextsOffset: 0,
    createContextsLength: 0
  )
  
  let pipeNameUtf16 = toUtf16LE(pipeName)
  
  createReq.nameLength = pipeNameUtf16.len.uint16
  var cReq = newSeqUninit[uint8](56)
  copyMem(cReq[0].addr, createReq.addr, sizeof(createReq)-1)
  
  createData.add(cReq)
  createData.add(pipeNameUtf16)

  client.sendNetbiosHeader(createData.len.uint32)
  client.socket.send(cast[string](createData))

  let response = client.recvSMB2Message()
  if response.len == 0:
    raise newException(IOError, "[-] Failed to Receive Create Response")

  # Parse response
  let status = cast[uint32]([response[8], response[9], response[10], response[11]])
  if status != 0:
    raise newException(IOError, "[-] Failed to Open Pipe: 0x" & status.toHex)

  # Get both persistent and volatile file IDs
  let persistentHandle = cast[uint64]([
    response[0x80], response[0x81], response[0x82], response[0x83],
    response[0x84], response[0x85], response[0x86], response[0x87]
  ])
  
  let volatileHandle = cast[uint64]([
    response[0x88], response[0x89], response[0x8A], response[0x8B],
    response[0x8C], response[0x8D], response[0x8E], response[0x8F]
  ])
  
  #echo "Debug - Persistent: 0x" & persistentHandle.toHex
  #echo "Debug - Volatile: 0x" & volatileHandle.toHex

  result = (persistent: persistentHandle, volatile: volatileHandle)

proc bindRPC(client: SmbClient, fileId: tuple[persistent, volatile: uint64]): bool = 
  let srvsvcUuid = [0xc8'u8, 0x4f, 0x32, 0x4b, 0x70, 0x16, 0xd3, 0x01, 0x12, 0x78, 0x5a, 0x47, 0xbf, 0x6e, 0xe1, 0x88]
  let ndr32Uuid = [0x04'u8, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11, 0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60]
  let ndr64Uuid = [0x33'u8, 0x05, 0x71, 0x71, 0xba, 0xbe, 0x37, 0x49, 0x83, 0x19, 0xb5, 0xdb, 0xef, 0x9c, 0xcc, 0x36]
  let bindTimeFeatureNegoUuid = [0x2c'u8, 0x1c, 0xb7, 0x6c, 0x12, 0x98, 0x40, 0x45, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
  
  var header = SMB2Header(
    protocol: SMB2_MAGIC,
    structureSize: 64,
    creditCharge: 1,
    command: SMB2_WRITE,
    credits: 1,
    flags: 0,
    nextCommand: 0,
    messageId: client.messageId,
    processId: 0xFEFF,
    treeId: client.treeId,
    sessionId: client.sessionId,
    signature: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
  )
  inc client.messageId
  
  var smbWriteRequest = SMB2WriteRequest(
    structureSize: 49,
    dataOffset: 0x70,
    # Length needs to be added later
    offset: 0,
    # fileID probably also needs to be added later
    channel: 0,
    remainingBytes: 0,
    writeChannelInfoOffset: 0,
    writeChannelInfoLength: 0,
    flags: 0
  )
  
  var bindPDU = PDUBind()
  bindPDU.header.version = 5
  bindPDU.header.minorVersion = 0
  bindPDU.header.pType = 11
  bindPDU.header.pFlags = 3
  bindPDU.header.dRep = [0x10'u8, 0, 0, 0]
  bindPDU.header.fragLength = 72
  bindPDU.header.authLength = 0
  bindPDU.header.callID = 0
  bindPDU.maxXmitFrag = 4280
  bindPDU.maxRecvFrag = 4280
  bindPDU.assocGroupID = 0
  bindPDU.numContextElements = 3

  var srvsvcNdr32 = presContextElement()
  srvsvcNdr32.contextID = 0
  srvsvcNdr32.numTransSyntaxes = 1
  srvsvcNdr32.padding = 0
  srvsvcNdr32.absSyntax.ifUUID = srvsvcUuid
  srvsvcNdr32.absSyntax.ifVersion = 3
  srvsvcNdr32.absSyntax.ifMinorVersion = 0
  srvsvcNdr32.transSyntax.ifUUID = ndr32Uuid
  srvsvcNdr32.transSyntax.ifVersion = 2
  srvsvcNdr32.transSyntax.ifMinorVersion = 0

  var srvsvcNdr64 = presContextElement()
  srvsvcNdr64.contextID = 1
  srvsvcNdr64.numTransSyntaxes = 1
  srvsvcNdr64.padding = 0
  srvsvcNdr64.absSyntax.ifUUID = srvsvcUuid
  srvsvcNdr64.absSyntax.ifVersion = 3
  srvsvcNdr64.absSyntax.ifMinorVersion = 0
  srvsvcNdr64.transSyntax.ifUUID = ndr64Uuid
  srvsvcNdr64.transSyntax.ifVersion = 1
  srvsvcNdr64.transSyntax.ifMinorVersion = 0
 
  var bindTimeNego = presContextElement()
  bindTimeNego.contextID = 2
  bindTimeNego.numTransSyntaxes = 1
  bindTimeNego.padding = 0
  bindTimeNego.absSyntax.ifUUID = srvsvcUuid
  bindTimeNego.absSyntax.ifVersion = 3
  bindTimeNego.absSyntax.ifMinorVersion = 0
  bindTimeNego.transSyntax.ifUUID = bindTimeFeatureNegoUuid
  bindTimeNego.transSyntax.ifVersion = 1
  bindTimeNego.transSyntax.ifMinorVersion = 0

  copyMem(smbWriteRequest.fileID[0].addr, fileId.persistent.addr, sizeof(fileId.persistent))
  copyMem(smbWriteRequest.fileID[8].addr, fileId.volatile.addr, sizeof(fileId.volatile))
  
  var bindReq = newSeqUninit[uint8](25)
  copyMem(bindReq[0].addr, bindPDU.addr, sizeof(bindPDU))

  # RPC bind data
  bindReq.add([0'u8, 0, 0]) # Padding to Align Data at boundary?
  
  var pConElem: array[44, uint8]
  copyMem(pConElem[0].addr, srvsvcNdr32.addr, sizeof(srvsvcNdr32))
  bindReq.add(pConElem)
  
  copyMem(pConElem[0].addr, srvsvcNdr64.addr, sizeof(srvsvcNdr64))
  bindReq.add(pConElem)

  copyMem(pConElem[0].addr, bindTimeNego.addr, sizeof(bindTimeNego))
  bindReq.add(pConElem)

  smbWriteRequest.length = bindReq.len.uint32

  var writeReq = newSeqUninit[uint8](48)
  copyMem(writeReq[0].addr, smbWriteRequest.addr, sizeof(smbWriteRequest))

  var tmp16: array[2, uint8]
  let bindReqLen16 = bindReq.len.uint16
  
  # Adjust frag length as well
  littleEndian16(tmp16[0].addr, bindReqLen16.addr)
  bindReq[8..9] = tmp16
  
  #[
  stdout.write("\nDCE/RPC Bind Request: ")
  for bindReqByte in bindReq: stdout.write(bindReqByte.toHex(2) & " ")
  echo "\n"
  ]#

  var writeData = packSMB2Header(header)
  writeData.add(writeReq)
  writeData.add(bindReq)
  
  client.sendNetbiosHeader(writeData.len.uint32)
  client.socket.send(cast[string](writeData))
  let response = client.recvSMB2Message()
  if response.len == 0:
    raise newException(IOError, "[-] Remote Server Did Not Respond to RPC Bind Request!")
  
  let status = cast[uint32]([response[8], response[9], response[10], response[11]])
  if status == 0:
    #echo "Successfully Sent RPC Bind!"
    return status == 0

  echo "\n[-] Remote Server Returned an Error: 0x", toHex(status)
  return false

proc readBindAck(client: SmbClient, fileId: tuple[persistent, volatile: uint64]): bool =
  var header = SMB2Header(
    protocol: SMB2_MAGIC,
    structureSize: 64,
    creditCharge: 1,
    command: SMB2_READ,  # 0x08
    credits: 1,
    flags: 0,
    nextCommand: 0,
    messageId: client.messageId,
    processId: 0xFEFF,
    treeId: client.treeId,
    sessionId: client.sessionId,
    signature: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
  )
  inc client.messageId
  
  var smbReadRequest = SMB2ReadRequest(
    structureSize: 49,
    padding: 0x50,
    flags: 0,
    length: 1024,
    offset: 0,
    # Add FileID later
    minimumCount: 0,
    channel: 0,
    remainingBytes: 0,
    readChannelInfoOffset: 0,
    readChannelInfoLength: 0
  )

  copyMem(smbReadRequest.fileID[0].addr, fileId.persistent.addr, sizeof(fileId.persistent))

  copyMem(smbReadRequest.fileID[8].addr, fileId.volatile.addr, sizeof(fileId.volatile))

  var readReq = newSeqUninit[uint8](48)
  copyMem(readReq[0].addr, smbReadRequest.addr, sizeof(smbReadRequest))
  
  readReq.add(0x00'u8)                            # Padding?
  
  #echo "Using FileId - Persistent: 0x", fileId.persistent.toHex
  #echo "Using FileId - Volatile: 0x", fileId.volatile.toHex

  var writeData = packSMB2Header(header)
  writeData.add(readReq)
  
  client.sendNetbiosHeader(writeData.len.uint32)
  client.socket.send(cast[string](writeData))

  let response = client.recvSMB2Message()
  if response.len == 0:
    return false

  # Check for successful response and bind_ack
  let status = cast[uint32]([response[8], response[9], response[10], response[11]])
  #echo "ReadBindAck Response Status: 0x", toHex(status)
  return status == 0

proc isValidShareName(s: string): bool =
  ## Checks if a share name meets the specified requirements.
  ## Returns true if the name is valid, false otherwise.

  # Check length
  if s.len == 0 or s.len > 80:
    return false

  # Define illegal characters as a string
  const illegalChars = r"""\/[]:¦<>=;,*?"""

  # Check for illegal characters
  for c in s:
    if c in illegalChars:
      return false

  # Check for control characters (0x00 through 0x1F)
  for c in s:
    if c <= '\x1F':
      return false

  # If all checks pass, the name is valid
  return true

proc extractShareNames(data: seq[uint8]): seq[string] =
  ## Extracts share names from an SMB2 IoCTL Response message.
  ## Dynamically parses the SMB2 header and structures to locate the Blob Offset.

  # SMB2 Header structure offsets
  const
    SMB2_HEADER_SIZE = 64
    SMB2_IOCTL_OFFSET = SMB2_HEADER_SIZE + 0x14  # Offset to the Blob Offset in the IOCTL Response

  # Ensure the data is large enough to contain the SMB2 header and IOCTL structure
  if data.len < SMB2_IOCTL_OFFSET + 4:
    raise newException(ValueError, "Data is too small to contain a valid SMB2 IOCTL Response")

  # Extract the Blob Offset (4 bytes starting at SMB2_IOCTL_OFFSET)

  let blobOffset = cast[uint32]([data[SMB2_IOCTL_OFFSET], data[SMB2_IOCTL_OFFSET+1], data[SMB2_IOCTL_OFFSET+2], data[SMB2_IOCTL_OFFSET+3]])
  # Ensure the Blob Offset is within the data bounds
  if blobOffset.int >= data.len:
    raise newException(ValueError, "Blob Offset is out of bounds")

  # Locate the DCE/RPC Response using the Blob Offset
  let dceRpcResponse = data[(SMB2_IOCTL_OFFSET + 16 + blobOffset).int ..< data.len]
  #[
  echo "\n"
  for resBytes in dceRpcResponse: stdout.write(toHex(resBytes, 2))
  echo "\n"
  ]#

  # Extract Unicode strings (share names) from the DCE/RPC Response
  var i = 132 # Offset from DCE/RPC Response Header
  while i < dceRpcResponse.len - 1:
    if dceRpcResponse[i] != 0 and dceRpcResponse[i + 1] == 0:  # Unicode string start
      var str = ""
      while i < dceRpcResponse.len - 1 and dceRpcResponse[i] != 0:
        str.add(char(dceRpcResponse[i]))
        i += 2
      if str.isValidShareName:
        result.add(str)
    else:
      i += 1

proc readUint32Le(data: openArray[uint8], pos: int): uint32 =
  result = uint32(data[pos]) or
           uint32(data[pos + 1]) shl 8 or
           uint32(data[pos + 2]) shl 16 or
           uint32(data[pos + 3]) shl 24

proc readUtf16String(data: openArray[uint8], pos: int, numChars: int): tuple[str: string, bytesRead: int] =
  var bytes = newSeq[uint8]()
  let byteCount = numChars * 2  # Each UTF16 char is 2 bytes
  
  # Read exact number of character pairs
  var i = 0
  while i < byteCount and pos + i + 1 < data.len:
    let b1 = data[pos + i]
    let b2 = data[pos + i + 1]
    
    # Stop at null terminator
    if b1 == 0 and b2 == 0:
      break
      
    bytes.add(b1)
    bytes.add(b2)
    i += 2
  
  if bytes.len > 0:
    try:
      result.str = cast[string](bytes)
    except:
      result.str = ""
  
  # Always read full character count for position tracking
  result.bytesRead = ((byteCount + 7) and not 7)

proc parseShares*(data: openArray[uint8]): seq[Share] =
  result = newSeq[Share]()
  var pos = 0x140
  
  while pos + 8 <= data.len:
    var share = Share()
    
    # Read share name length (4 bytes + 4 padding)
    let nameLen = readUint32Le(data, pos)
    pos += 8
    
    if nameLen == 0 or nameLen > 100:  # Sanity check
      continue
      
    # Read name string
    let (name, nameBytes) = readUtf16String(data, pos, int(nameLen))
    if name.len == 0:
      pos += nameBytes
      continue
      
    share.name = name
    pos += nameBytes
    
    # Read description length
    if pos + 8 > data.len:
      continue
      
    let descLen = readUint32Le(data, pos)
    pos += 8
    
    # Read description if present
    if descLen > 1 and pos + (descLen * 2).int <= data.len:
      let (desc, descBytes) = readUtf16String(data, pos, int(descLen))
      share.description = desc
      pos += descBytes
    else:
      pos += 8
      
    # Skip type field
    pos += 8
    
    # Only add if we got a valid name
    if share.name.len > 0:
      result.add(share)

proc sendNetShareEnumAll(client: SmbClient, fileId: tuple[persistent, volatile: uint64]): seq[Share] =
 var header = SMB2Header(
   protocol: SMB2_MAGIC,
   structureSize: 64,
   creditCharge: 1,
   command: SMB2_IOCTL,
   credits: 1,
   flags: 0,
   nextCommand: 0,
   messageId: client.messageId,
   processId: 0xFEFF,
   treeId: client.treeId,
   sessionId: client.sessionId,
   signature: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
 )
 inc client.messageId

 var smbIoctlRequest = SMB2IoctlRequest(
  structureSize: 57,
  reserved: 0,
  ctlCode: 0x0011C017,
  # Add file ID later
  inputOffset: 0x78,
  # Add input count later
  maxInputResponse: 0,
  outputOffset: 0,
  outputCount: 0,
  maxOutputResponse: 1024,
  flags: 1,
  reserved2: 0
 )
 
 var rpcRequest = PDURequest()
 rpcRequest.header.version = 5
 rpcRequest.header.minorVersion = 0
 rpcRequest.header.pType = 0
 rpcRequest.header.pFlags = 3
 rpcRequest.header.dRep = [0x10'u8, 0, 0, 0]
 rpcRequest.header.fragLength = 0x6c
 rpcRequest.header.authLength = 0
 rpcRequest.header.callID = 2
 rpcRequest.allocHint = 0x70
 rpcRequest.contextID = 1
 rpcRequest.opNum = 15

 copyMem(smbIoctlRequest.fileID[0].addr, fileId.persistent.addr, sizeof(fileId.persistent))

 copyMem(smbIoctlRequest.fileID[8].addr, fileId.volatile.addr, sizeof(fileId.volatile))
 
 var rpcReq = newSeqUninit[uint8](24)
 copyMem(rpcReq[0].addr, rpcRequest.addr, sizeof(rpcRequest))

 # Server name parameter
 rpcReq.add([0x00'u8, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00])  # Referent ID
 rpcReq.add([0x0c'u8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])      # Max count
 rpcReq.add([0x00'u8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])      # Offset
 rpcReq.add([0x0c'u8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])      # Actual count
 
 # Server name string
 rpcReq.add(toUtf16LE("\\\\" & client.host & "\0"))
 
 # Level and share info
 rpcReq.add([0x01'u8, 0x00, 0x00, 0x00])      # Level = 1
 rpcReq.add([0x00'u8, 0x00, 0x00, 0x00])      # No idea what to call this. Not padding. Identifying a structure (container/ ctr)?
 rpcReq.add([0x01'u8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])  # Container pointer (referent id)
 rpcReq.add([0x00'u8, 0x00, 0x02, 0x00])      # No idea what to call this. Not padding. Array size? Wireshark says "count"
 rpcReq.add([0x00'u8, 0x00, 0x00, 0x00])      # Padding
 rpcReq.add([0x00'u8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])  # Buffer pointer

 # Max Buffer
 rpcReq.add([0x00'u8, 0x00, 0x00, 0x00])
 rpcReq.add([0x00'u8, 0x00, 0x00, 0x00])      # Padding

 # Resume Handle
 rpcReq.add([0xff'u8, 0xff, 0xff, 0xff, 0x00'u8, 0x00, 0x00, 0x00]) # Referent ID
 rpcReq.add([0x00'u8, 0x00, 0x00, 0x00])      # Resume Handle Value
 rpcReq.add([0x00'u8, 0x00, 0x00, 0x00])      # Padding ?

 # Build IOCTL Request
 var ioctlReq = newSeqUninit[uint8](56)

 # Write length should be the size of rpcReq
 var tmp16: array[2, uint8]
 var rpcReqLen16 = rpcReq.len.uint16

 smbIoctlRequest.inputCount = rpcReq.len.uint32
 copyMem(ioctlReq[0].addr, smbIoctlRequest.addr, sizeof(smbIoctlRequest))

 # Adjust frag length as well
 littleEndian16(tmp16[0].addr, rpcReqLen16.addr)
 rpcReq[8..9] = tmp16
 
 var writeData = packSMB2Header(header)
 writeData.add(ioctlReq)
 writeData.add(rpcReq)

 client.sendNetbiosHeader(writeData.len.uint32)
 client.socket.send(cast[string](writeData))

 let response = client.recvSMB2Message()
 if response.len == 0:
   return @[]

 let status = cast[uint32]([response[8], response[9], response[10], response[11]])
 if status == 0:
    #echo "Successfully Sent RPC Request (NetrShareEnum)!"
    #result = extractShareNames(response)
    result = parseShares(response)

    #echo "Successfully parsed NetShareEnum response"
    #echo "Number of shares found: ", result.entriesRead
    
    #for share in result.shares:
    #  echo "\nShare Details:"
    #  echo "  Name: ", share.netname
    #  if share.remark.len > 0:
    #    echo "  Description: ", share.remark

    return result

 #echo "RPC Request Response Status: 0x", toHex(status)

proc listShares*(client: SmbClient): seq[Share] =
  #result = @[]
  var fileId: tuple[persistent, volatile: uint64]

  try:
    # Connect to IPC$
    client.connectToShare("IPC$")
    
    # Open SRVSVC pipe
    fileId = client.openNamedPipe("srvsvc")
    
    # Bind to SRVSVC interface
    if not client.bindRPC(fileId): return
    
    # Read from SRVSVC pipe for Bind Acknowledgement Response
    if not client.readBindAck(fileId):
        echo "\n[-] Did Not Receive Bind Acknowledgement From Server!"
        return @[]
    
    result = client.sendNetShareEnumAll(fileId) # Send NetShareEnum request
    return result
    
  finally:
    if client.treeId != 0:
      var header = SMB2Header(
        protocol: SMB2_MAGIC,
        structureSize: 64,
        creditCharge: 1,
        command: SMB2_CLOSE,
        credits: 1,
        flags: 0,
        nextCommand: 0,
        messageId: client.messageId,
        processId: 0xFEFF,
        treeId: client.treeId,
        sessionId: client.sessionId,
        signature: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
      )
      inc client.messageId
      
      var disconnectData = packSMB2Header(header)
      disconnectData.add(cast[array[2, uint8]](24'u16)) # StructureSize
      disconnectData.add([0'u8, 0]) # Flags
      disconnectData.add([0'u8, 0, 0, 0]) # Reserved
      disconnectData.add(cast[array[8, uint8]](fileId.persistent))
      disconnectData.add(cast[array[8, uint8]](fileId.volatile))
      echo "\n[*] Disconnecting From IPC$"
      client.sendNetbiosHeader(disconnectData.len.uint32)
      client.socket.send(cast[string](disconnectData))
      client.treeId = 0

when isMainModule:
  let client = newSmbClient("10.0.0.48")
  try:
    # Connect with password
    #client.connect("user", password = "password")
    # Or with NTLM hash
     client.connect("user", ntlmHash = "8846F7EAEE8FB117AD06BDD830B7586C")
    
     let shares = client.listShares()
     echo "\nFinal results:"
     for share in shares:
      echo "\nShare Name: ", share.name
      if share.description.len > 0:
        echo "Description: ", share.description
      echo "---"
      
  except: echo "[-] Error: ", getCurrentExceptionMsg()
  finally: client.disconnect()
