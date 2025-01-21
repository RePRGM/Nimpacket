import std/[net, strutils, endians, strformat, tables] 
import hashlib/rhash/[md4, md5]
import 
  ../NLMP/nlmp, 
  ../utils/utils,
  ../RPC/rpc, 
  ../GSSAPI/gssapi,
  ./types

from std/sequtils import concat, mapIt, toSeq

proc withSignature*[T](builder: var SMB2RequestBuilder[T], signature: array[16, uint8]): var SMB2RequestBuilder[T] =
  builder.header.signature = signature
  return builder

# Write request specific builders
proc newWriteRequest*(client: SmbClient): SMB2RequestBuilder[SMB2WriteRequest] =
  result.client = client
  result.header = SMB2Header(command: SMB2_WRITE, sessionID: client.sessionId, messageId: client.messageId, treeID: client.treeId)
  result.request = SMB2WriteRequest()
  inc client.messageId

proc withFileId*(builder: var SMB2RequestBuilder[SMB2WriteRequest], fileId: tuple[persistent, volatile: uint64]): var SMB2RequestBuilder[SMB2WriteRequest] =
  copyMem(builder.request.fileId[0].addr, fileId.persistent.addr, 8)
  copyMem(builder.request.fileId[8].addr, fileId.volatile.addr, 8)
  return builder

proc withData*(builder: var SMB2RequestBuilder[SMB2WriteRequest], data: openArray[byte]): var SMB2RequestBuilder[SMB2WriteRequest] =
  builder.request.length = data.len.uint32
  builder.data = @data
  return builder

proc withOffset*(builder: var SMB2RequestBuilder[SMB2WriteRequest], offset: uint64): var SMB2RequestBuilder[SMB2WriteRequest] =
  builder.request.offset = offset
  return builder

# Read request specific builders
proc newReadRequest*(client: SmbClient): SMB2RequestBuilder[SMB2ReadRequest] =
  result.client = client
  result.header = SMB2Header(command: SMB2_READ, sessionID: client.sessionId, messageId: client.messageId, treeID: client.treeId)
  result.request = SMB2ReadRequest()
  inc client.messageId

proc withLength*(builder: var SMB2RequestBuilder[SMB2ReadRequest], length: uint32): var SMB2RequestBuilder[SMB2ReadRequest] =
  builder.request.length = length
  return builder

# Session Setup specific builders
proc newSessionSetupRequest*(client: SmbClient): SMB2RequestBuilder[SMB2SESSION_SETUP_REQUEST] = 
  var sessionSetupReq = SMB2RequestBuilder[SMB2SESSION_SETUP_REQUEST]()
  sessionSetupReq.client = client
  sessionSetupReq.header = SMB2Header(command: SMB2_SESSION_SETUP, messageId: client.messageId, sessionID: client.sessionId)
  sessionSetupReq.request = SMB2SESSION_SETUP_REQUEST()
  inc client.messageId
  return sessionSetupReq

proc withLength*(builder: var SMB2RequestBuilder[SMB2SESSION_SETUP_REQUEST], length: uint16): var SMB2RequestBuilder[SMB2SESSION_SETUP_REQUEST] =
  builder.request.securityBufferLength = length
  return builder

proc withOffset*(builder: var SMB2RequestBuilder[SMB2SESSION_SETUP_REQUEST], offset: uint16): var SMB2RequestBuilder[SMB2SESSION_SETUP_REQUEST] = 
  builder.request.securityBufferOffset = offset
  return builder

# Negotiate request specific builders
proc newNegotiateRequest*(client: SmbClient): SMB2RequestBuilder[SMB2NegotiateRequest] =
  result.client = client
  result.header = SMB2Header(command: SMB2_NEGOTIATE)
  result.request = SMB2NegotiateRequest()
  inc client.messageId

# Tree_Connect request specific builders
proc newTreeConnectRequest*(client: SmbClient): SMB2RequestBuilder[SMB2TreeConnectRequest] =
  var treeconReq = SMB2RequestBuilder[SMB2TreeConnectRequest]()
  treeconReq.client = client
  treeconReq.header = SMB2Header(command: SMB2_TREE_CONNECT, sessionID: client.sessionId, messageId: client.messageId)
  treeconReq.request = SMB2TreeConnectRequest()
  inc client.messageId
  return treeconReq

# Create request specific builders
proc newCreateRequest*(client: SmbClient): SMB2RequestBuilder[SMB2CreateRequest] =
  result.client = client
  result.header = SMB2Header(command: SMB2_CREATE, sessionID: client.sessionId, messageId: client.messageId, treeID: client.treeId)
  result.request = SMB2CreateRequest()
  inc client.messageId

proc newIoctlRequest*(client: SmbClient): SMB2RequestBuilder[SMB2IoctlRequest] =
  result.client = client
  result.header = SMB2Header(command: SMB2_IOCTL, sessionID: client.sessionId, messageId: client.messageId, treeID: client.treeId)
  result.request = SMB2IoctlRequest()
  inc client.messageId

proc newSrvSvcRPCBind*(): seq[uint8] =
  let srvsvcUuid = [0xc8'u8, 0x4f, 0x32, 0x4b, 0x70, 0x16, 0xd3, 0x01, 0x12, 0x78, 0x5a, 0x47, 0xbf, 0x6e, 0xe1, 0x88]
  let ndr32Uuid = [0x04'u8, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11, 0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60]
  let ndr64Uuid = [0x33'u8, 0x05, 0x71, 0x71, 0xba, 0xbe, 0x37, 0x49, 0x83, 0x19, 0xb5, 0xdb, 0xef, 0x9c, 0xcc, 0x36]
  let bindTimeFeatureNegoUuid = [0x2c'u8, 0x1c, 0xb7, 0x6c, 0x12, 0x98, 0x40, 0x45, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]

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

  var tmp16: array[2, uint8]
  let bindReqLen16 = bindReq.len.uint16
  
  # Adjust frag length
  littleEndian16(tmp16[0].addr, bindReqLen16.addr)
  bindReq[8..9] = tmp16

  return bindReq

proc build*[T](builder: SMB2RequestBuilder[T]): seq[uint8] =
  if builder.data.len != 0:
    result = newSeqUninit[uint8]((sizeof(builder.header)+sizeof(builder.request)) + builder.data.len)
    copyMem(result[0].addr, builder.header.addr, sizeof(builder.header))
    copyMem(result[64].addr, builder.request.addr, sizeof(builder.request))
    copyMem(result[64 + sizeof(builder.request)].addr, builder.data[0].addr, builder.data.len)
  else:
    result = newSeqUninit[uint8](sizeof(builder.header)+sizeof(T))
    copyMem(result[0].addr, builder.header.addr, sizeof(builder.header))
    copyMem(result[64].addr, builder.request.addr, sizeof(T))

proc packSMB2Header*(header: SMB2Header): seq[uint8] =
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

proc disconnect*(client: SmbClient) =
  if client.connected:
    client.socket.close()
    client.connected = false
    client.sessionId = 0
    client.treeId = 0

proc sendNetbiosHeader*(client: SmbClient, length: uint32) =
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

proc parseSessionSetupResponse*(response: seq[uint8]): tuple[status: uint32, sessID: uint64, securityBlob: seq[uint8]] =
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

proc recvSMB2Message*(client: SmbClient): seq[uint8] =
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

proc send*(client: SmbClient, request: seq[uint8]): tuple[response: seq[uint8], status: uint32] =
  client.sendNetbiosHeader(request.len.uint32)
  client.socket.send(cast[string](request))

  let response = client.recvSMB2Message()
  if response.len == 0:
    raise newException(IOError, "No Response from Server!")
  let status = cast[uint32]([response[8], response[9], response[10], response[11]])

  return (response, status)

proc sendSMB2SessionSetup*(client: SmbClient, token: seq[uint8]): seq[uint8] =
  var initialReq = client.newSessionSetupRequest()
  initialReq.data.add(token)
  #echo "TOken length: ", token.len
  var reqBytes = initialReq.withOffset(88).withLength(token.len.uint16).build()
  var (setupRes, setupStatus) = client.send(reqBytes)

  #[
  echo "Sending session setup packet of size: ", smbPayload.len
  stdout.write("Session setup packet: ")
  for b in smbPayload:
    stdout.write(b.toHex(2))
  stdout.write("\n")
  ]#

  return setupRes

proc sessionSetup*(client: SmbClient, username: string, ntlmHash: string): bool =
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

proc recvTreeID*(response: seq[uint8]): uint32 = 
 let treeId = cast[uint32]([response[36], response[37], response[38], response[39]])
 if treeId != 0: result = treeId
 else: result = 0

proc connect*(client: SmbClient, username = "", password = "", ntlmHash = "") =
  if not client.connected:
    echo "[*] Connecting to ", client.host, ":", client.port
    client.socket.connect(client.host, client.port)
    client.socket.setSockOpt(OptKeepAlive, true)
    client.connected = true
    echo "[+] Connection Established at ", client.host, ":", client.port

    # Send Negotiate Protocol Request
    #client.messageId = 1
    var negReq = client.newNegotiateRequest.build()
    var (negRes, negStatus) = client.send(negReq)
    if negStatus != 0:
      client.disconnect()
      raise newException(IOError, "[-] SMB2 Negotiate Failed with Error 0x" & toHex(negStatus))

    #if not client.sendSMB2Negotiate():
    #  client.disconnect()
    #  raise newException(IOError, "[-] SMB2 Negotiate Failed")

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
      raise newException(IOError, "[-] SMB2 Session Setup Failed")

    echo "\n[+] Successfully Authenticated as ", client.ntlmState.username

proc connectToShare*(client: SmbClient, share: string): void =
  if not client.connected:
    raise newException(IOError, "[-] Not Connected to Server")
  
  echo "\n[*] Connecting to \\\\", client.host, r"\", share
  let sharePath = toUtf16LE(r"\\" & client.host & r"\" & share)
  var treeConReq = client.newTreeConnectRequest()
  treeConReq.data = sharePath
  treeConReq.request.pathLength = sharePath.len.uint16
  treeConReq.request.pathOffset = 72
  var treeConReqBytes = treeConReq.build()
  var (treeConRes, treeConStatus) = client.send(treeConReqBytes)
  if treeConStatus == 0:
    client.treeId = recvTreeID(treeConRes)
    echo r"[*] Successfully Connected to \\", client.host, r"\", share
  else:
    client.disconnect()
    raise newException(IOError, "[-] Tree Connect Failed with Status: 0x" & $treeConStatus)

proc openNamedPipe*(client: SmbClient, pipeName: string): tuple[persistent, volatile: uint64] =
  let pipeNameUtf16 = toUtf16LE(pipeName)
  var createRequest = client.newCreateRequest()
  createRequest.request.desiredAccess = 0x0012019F
  createRequest.request.shareAccess = 7
  createRequest.request.impersonationLevel = 2
  createRequest.request.createDisposition = 1
  createRequest.request.nameOffset = 120
  createRequest.request.nameLength = pipeNameUtf16.len.uint16
  createRequest.data = pipeNameUtf16
  
  var crReqBytes = createRequest.build()
  var (crRes, crStatus) = client.send(crReqBytes)
  
  # Parse response
  if crStatus != 0:
    raise newException(IOError, "[-] Failed to Open Pipe: 0x" & crStatus.toHex)

  # Get both persistent and volatile file IDs
  let persistentHandle = cast[uint64]([
    crRes[0x80], crRes[0x81], crRes[0x82], crRes[0x83],
    crRes[0x84], crRes[0x85], crRes[0x86], crRes[0x87]
  ])
  
  let volatileHandle = cast[uint64]([
    crRes[0x88], crRes[0x89], crRes[0x8A], crRes[0x8B],
    crRes[0x8C], crRes[0x8D], crRes[0x8E], crRes[0x8F]
  ])
  
  #echo "Debug - Persistent: 0x" & persistentHandle.toHex
  #echo "Debug - Volatile: 0x" & volatileHandle.toHex

  result = (persistent: persistentHandle, volatile: volatileHandle)

proc bindRPC*(client: SmbClient, fileId: tuple[persistent, volatile: uint64], bindReq: seq[uint8]): bool = 
  var smbWriteReq = client.newWriteRequest()
  smbWriteReq.request.length = bindReq.len.uint32
  smbWriteReq.request.dataOffset = 0x70
  copyMem(smbWriteReq.request.fileID[0].addr, fileId.persistent.addr, sizeof(fileId.persistent))
  copyMem(smbWriteReq.request.fileID[8].addr, fileId.volatile.addr, sizeof(fileId.volatile))
  
  smbWriteReq.data = bindReq
  let smbWRBytes = smbWriteReq.build()
  let (bindRes, bindResStatus) = client.send(smbWRBytes)
  return bindResStatus == 0

proc readBindAck*(client: SmbClient, fileId: tuple[persistent, volatile: uint64]): bool =
  var readReq = client.newReadRequest()

  copyMem(readReq.request.fileId[0].addr, fileId.persistent.addr, 8)
  copyMem(readReq.request.fileId[8].addr, fileId.volatile.addr, 8)
  var readReqBytes = readReq.build()
  readReqBytes.add(0x00'u8) # Padding?
  
  var (readRes, readResStatus) = client.send(readReqBytes)
  return readResStatus == 0

proc parseShares*(data: openArray[uint8]): seq[Share] =
  result = newSeq[Share]()
  var pos = 0x140 #0x140
  var currentShare = Share()
  var isName = true  # Track whether we're reading a name or description
  
  while pos + 8 <= data.len:
    # Read string length
    let length = readUint32Le(data, pos)
    pos += 8
    
    if length == 0 or length > 100:  # Sanity check
      continue
    
    # Read the string
    let (str, bytesRead) = readUtf16String(data, pos, int(length))
    pos += bytesRead
    
    if str.len > 0:
      if isName:
        # Starting new share
        if currentShare.name.len > 0:
          result.add(currentShare)
        currentShare = Share()
        currentShare.name = str
      else:
        # Add description to current share
        currentShare.description = str
        result.add(currentShare)
        currentShare = Share()
        
    # Skip 8 bytes between each string
    pos += 8
    isName = not isName
  
  # Add final share if pending
  if currentShare.name.len > 0:
    result.add(currentShare)

proc sendNetShareEnumAll*(client: SmbClient, fileId: tuple[persistent, volatile: uint64]): seq[uint8] =
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

 var rpcReq = newSeqUninit[uint8](24)
 copyMem(rpcReq[0].addr, rpcRequest.addr, sizeof(rpcRequest))

 ## Server name parameter
 #rpcReq.add([0x00'u8, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00])  # Referent ID
 #rpcReq.add([0x0c'u8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])      # Max count
 #rpcReq.add([0x00'u8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])      # Offset
 #rpcReq.add([0x0c'u8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])      # Actual count
 #
 ## Server name string
 #rpcReq.add(toUtf16LE("\\\\" & client.host & "\0"))
 #
 ## Level and share info
 #rpcReq.add([0x01'u8, 0x00, 0x00, 0x00])      # Level = 1
 #rpcReq.add([0x00'u8, 0x00, 0x00, 0x00])      # No idea what to call this. Not padding. Identifying a structure (container/ ctr)?
 #rpcReq.add([0x01'u8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])  # Container pointer (referent id)
 #rpcReq.add([0x00'u8, 0x00, 0x02, 0x00])      # No idea what to call this. Not padding. Array size? Wireshark says "count"
 #rpcReq.add([0x00'u8, 0x00, 0x00, 0x00])      # Padding
 #rpcReq.add([0x00'u8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])  # Buffer pointer
#
 ## Max Buffer
 #rpcReq.add([0x00'u8, 0x00, 0x00, 0x00])
 #rpcReq.add([0x00'u8, 0x00, 0x00, 0x00])      # Padding
#
 ## Resume Handle
 #rpcReq.add([0xff'u8, 0xff, 0xff, 0xff, 0x00'u8, 0x00, 0x00, 0x00]) # Referent ID
 #rpcReq.add([0x00'u8, 0x00, 0x00, 0x00])      # Resume Handle Value
 #rpcReq.add([0x00'u8, 0x00, 0x00, 0x00])      # Padding ?
 
 var ctx = NDRContext(data: @[], position: 0, nextRefId: 1, pointerMap: initTable[pointer, uint32]())
 encodeInt32(ctx, Level1.ord)
 echo "ctx.data (Level1 Enum): ", ctx.data
 let servername = r"\\" & client.host
 
 let container = SHARE_INFO_1_CONTAINER(EntriesRead: 0x00_02_00_00, Buffer: nil)
 let enumStruct = ShareEnumUnion(level: Level1, level1: container.addr)
 
 let tempVal = 0x123'u32
 let rpc = NetrShareEnum(servername, addr enumStruct)
 #let rpc = NetrShareEnum(servername, addr enumStruct, 0xFFFFFFFF'u32)
 rpcReq.add(rpc)

 # Print hex dump for verification
 echo "Encoded data (hex):"
 for i, b in rpc:
  stdout.write(fmt"{b:02x} ")
  if (i + 1) mod 16 == 0:
    echo ""

 var tmp16: array[2, uint8]
 let rpcReqLen16 = rpcReq.len.uint16
 #let rpcReqLen16 = 112'u16
 # Adjust frag length
 littleEndian16(tmp16[0].addr, rpcReqLen16.addr)
 rpcReq[8..9] = tmp16
 
 var ioctlReq = client.newIoctlRequest()
 ioctlReq.request.ctlCode = 0x0011C017
 ioctlReq.request.inputCount = rpcReq.len.uint32
 ioctlReq.request.flags = 1
 ioctlReq.data = rpcReq
 copyMem(ioctlReq.request.fileID[0].addr, fileId.persistent.addr, sizeof(fileId.persistent))
 copyMem(ioctlReq.request.fileID[8].addr, fileId.volatile.addr, sizeof(fileId.volatile))
 let ioctlReqBytes = ioctlReq.build()

 let (ioctlRes, ioctlResStatus) = client.send(ioctlReqBytes)
 if ioctlResStatus == 0:
    #echo "Successfully Sent RPC Request (NetrShareEnum)!"
    #result = parseShares(ioctlRes)
    result = ioctlRes
 else: echo "[-] Server Returned Error 0x", toHex(ioctlResStatus)
  
 return result

proc listShares*(client: SmbClient): seq[Share] =
  #result = @[]
  var fileId: tuple[persistent, volatile: uint64]
  let bindSrvsvc = newSrvSvcRPCBind()
  var netShareEnumRes: seq[uint8]
  try:
    # Connect to IPC$
    client.connectToShare("IPC$")
    
    # Open SRVSVC pipe
    fileId = client.openNamedPipe("srvsvc")
    
    # Bind to SRVSVC interface
    if not client.bindRPC(fileId, bindSrvsvc): return
    
    # Read from SRVSVC pipe for Bind Acknowledgement Response
    if not client.readBindAck(fileId):
        echo "\n[-] Did Not Receive Bind Acknowledgement From Server!"
        return @[]
    
    netShareEnumRes = client.sendNetShareEnumAll(fileId) # Send NetShareEnum request
    if netShareEnumRes.len == 0:
      echo "\n[-] Failed to Retrieve Share List!"
    else: result = parseShares(netShareEnumRes)
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
