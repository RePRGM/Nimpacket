import std/[net, strutils, endians, strformat, tables, options] 
import hashlib/rhash/[md4, md5]
import 
  ../NLMP/nlmp, 
  ../utils/utils,
  ../RPC/ndr,
  ../RPC/rpc, 
  ../ASN1/gssapi/main,
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
  bindPDU.header.pType = ptBind
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

proc initSMBSession*(client: SmbClient, username, ntlmHash: string): bool =
# sessionSetup() replacement code
#  if msgType == 1:
    # For Type 1 - NegTokenInit
  let type1Msg = createNTLMMsg(1, client.ntlmState.negotiateFlags.addr)
  
  var negTokenInit = SpnegoNegTokenInit()
  negTokenInit.mechTypes = @[OID_NTLMSSP]
  
  # Add NTLMSSP signature to the message
  var ntlmWithSig = @[0x4E'u8, 0x54, 0x4C, 0x4D, 0x53, 0x53, 0x50, 0x00]
  ntlmWithSig.add(type1Msg)
  negTokenInit.mechToken = some(ntlmWithSig)
  
  let spnegoToken = buildNegTokenInit(negTokenInit)
  let token = wrapGssApiToken(OID_SPNEGO, spnegoToken)
  
  let negoResponse = client.sendSMB2SessionSetup(token)
  let (status, sessionID, securityBlob) = parseSessionSetupResponse(negoResponse)

  #echo "Security Blob: "
  #dumpHex(securityBlob)

  client.sessionId = sessionID

  if status == 0xC0000016.uint32:
    let (serverChallenge, targetName, targetInfo) = parseNTLMChallengeMsg(securityBlob)
    let ntlmv2Response = calculateNTLMv2Response(ntlmHash, username, cast[string](targetName), serverChallenge, targetInfo)
    
    let type3Msg = createNTLMMsg(3, client.ntlmState.negotiateFlags.addr, username, targetName, ntlmv2Response)

  #elif msgType == 3:
    # For Type 3 - NegTokenResp (without negotiation state)
    var negTokenResp = SpnegoNegTokenResp()
    negTokenResp.responseToken = some(type3Msg)
    # Don't set negState to match your original
    
    let authTkn = buildNegTokenResp(negTokenResp)

    # Debug the structure
    #echo "\nType 3 SPNEGO Token (first 64 bytes):"
    #for i in 0..<min(64, authTkn.len):
    #  stdout.write(authTkn[i].toHex(2) & " ")
    #  if (i + 1) mod 16 == 0: echo ""
    #echo "\nTotal length: ", authTkn.len

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
      raise newException(IOError, "SMB2 Negotiate Failed with Error 0x" & toHex(negStatus))

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

    if not client.initSMBSession(username, actualNtlmHash):
      client.disconnect()
      raise newException(IOError, "SMB2 Session Setup Failed")

    echo "\n[+] Successfully Authenticated as ", client.ntlmState.username

proc connectToShare*(client: SmbClient, share: string): void =
  if not client.connected:
    raise newException(IOError, "Not Connected to Server")
  
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

proc parseNDR64String*(buf: NDRBuffer): string =
  ## Parse a single NDR64 conformant varying string
  ## NDR64 string header: 24 bytes total
  ## - 4 bytes maxCount + 4 bytes padding
  ## - 4 bytes offset + 4 bytes padding  
  ## - 4 bytes actualCount + 4 bytes padding
  
  let maxCount = decodeUint32(buf)
  discard decodeUint32(buf)  # padding
  
  let offset = decodeUint32(buf)
  discard decodeUint32(buf)  # padding
  
  let actualCount = decodeUint32(buf)
  discard decodeUint32(buf)  # padding
  
  if actualCount == 0:
    return ""
  
  # Read UTF-16LE string data
  result = ""
  for i in 0..<actualCount:
    let ch = decodeUint16(buf)
    if ch != 0 and ch < 128:
      result.add(chr(ch))
    elif ch != 0:
      result.add('?')  # Non-ASCII placeholder
  
  # Apply padding to align string data to 8-byte boundary
  let stringBytes = actualCount.int * 2
  let paddingNeeded = if stringBytes mod 8 == 0: 0 else: 8 - (stringBytes mod 8)
  
  for i in 0..<paddingNeeded:
    discard decodeUint8(buf)

proc parseShares*(response: seq[uint8]): seq[ShareInfo1] =
  #debugEcho "\n=== parseShares START ==="
  #debugEcho "Response length: ", response.len
  
  # Extract RPC response from SMB2 IOCTL response
  let outputOffset = response[96] or (response[97].uint32 shl 8) or 
                     (response[98].uint32 shl 16) or (response[99].uint32 shl 24)
  let outputCount = response[100] or (response[101].uint32 shl 8) or 
                    (response[102].uint32 shl 16) or (response[103].uint32 shl 24)
  
  #debugEcho fmt"Output Offset: {outputOffset}, Output Count: {outputCount}"
  
  if outputCount == 0:
    #debugEcho "No output data"
    return @[]
  
  let rpcResponse = response[outputOffset.int..<outputOffset.int + outputCount.int]
  let buf = newNDRBuffer()
  buf.data = rpcResponse
  
  # Skip PDU header and response fields
  let header = decodePDUHeader(buf)
  #debugEcho fmt"PDU Type: {header.pType}, Frag Length: {header.fragLength}"
  
  discard decodeUint32(buf)  # allocHint
  discard decodeUint16(buf)  # contextID
  discard decodeUint8(buf)   # cancelCount
  discard decodeUint8(buf)   # reserved
  
  # Main structure
  let level = decodeUint32(buf)
  let discriminant = decodeUint32(buf)
  let containerPtr = decodeUint32(buf)
  let totalEntriesPtr = decodeUint32(buf)
  let resumeHandlePtr = decodeUint32(buf)
  
  #debugEcho fmt"Level: {level}, ContainerPtr: 0x{containerPtr:08x}"
  #debugEcho fmt"Buffer position after main structure: {buf.position}"
  
  # Deferred data section
  
  # ResumeHandle's deferred data (if non-null)
  if resumeHandlePtr != 0:
    let resumeVal = decodeUint32(buf)
    #debugEcho fmt"Resume handle value: {resumeVal}"
  
  # Container's deferred data
  if containerPtr != 0:
    let entriesRead = decodeUint32(buf)
    #debugEcho fmt"EntriesRead: {entriesRead}"
    
    discard decodeUint32(buf)  # Padding
    
    let bufferPtr = decodeUint32(buf)
    #debugEcho fmt"BufferPtr: 0x{bufferPtr:08x}"
    
    discard decodeUint32(buf)  # Padding
    
    if bufferPtr != 0:
      # The array count
      let arrayCount = decodeUint32(buf)
      #debugEcho fmt"Array count: {arrayCount}"
      
      discard decodeUint32(buf)  # Skip padding after array count
      
      # Read ShareInfo1 structures (using NDR64 format)
      result = @[]
      var shareData: seq[tuple[netNameRef: uint64, shareType: uint32, remarkRef: uint64]] = @[]
      
      #debugEcho fmt"Reading {arrayCount} ShareInfo1 structures starting at position {buf.position}..."
      
      for i in 0..<arrayCount:
        # In NDR64, pointer references are 8 bytes
        let netNameRef = decodeUint64(buf)  # 8-byte pointer reference
        let shareType = decodeUint32(buf)   # 4-byte share type
        discard decodeUint32(buf)            # 4-byte padding
        let remarkRef = decodeUint64(buf)    # 8-byte pointer reference
        
        shareData.add((netNameRef, shareType, remarkRef))
        #debugEcho fmt"Share {i}: name=0x{netNameRef:016x}, type=0x{shareType:08x}, remark=0x{remarkRef:016x}"
      
      # Read string pairs for each share
      for i in 0..<arrayCount:
        var share = ShareInfo1()
        
        # Name and remark are in pairs, with 8-byte alignment after each string
        if shareData[i].netNameRef != 0:
          share.netName = parseNDR64String(buf)
          #debugEcho fmt"  Read netName: {share.netName}"
        
        if shareData[i].remarkRef != 0:
          share.remark = parseNDR64String(buf)
          #debugEcho fmt"  Read remark: {share.remark}"
        elif shareData[i].remarkRef == 0:
          # Empty remark still has a header with actualCount=1 (just null terminator)
          share.remark = parseNDR64String(buf)
          #debugEcho fmt"  Read empty remark"
        
        # Set share type
        share.shareType = cast[ShareType](shareData[i].shareType)
        
        result.add(share)
  
  #debugEcho "=== parseShares END ==="
  return result

proc encodeNDR32String*(buf: NDRBuffer, str: string) =
  ## Encode a string in NDR32 conformant/varying format
  ## Header is 12 bytes: maxCount(4) + offset(4) + actualCount(4)
  
  let wideStr = str.toUtf16LE()  # Convert to UTF-16LE
  let charCount = (wideStr.len div 2).uint32  # Number of wide characters including null
  
  # Write 12-byte header
  encodeUint32(buf, charCount)  # maxCount
  encodeUint32(buf, 0)          # offset
  encodeUint32(buf, charCount)  # actualCount
  
  # Write string data
  for b in wideStr:
    encodeUint8(buf, b)
  
  # Apply padding to align to 4-byte boundary
  let alignment = buf.position mod 4
  if alignment != 0:
    for i in 0..<(4 - alignment):
      encodeUint8(buf, 0)

proc sendNetShareEnumAll*(client: SmbClient, fileId: tuple[persistent, volatile: uint64]): seq[uint8] =
  let buf = newNDRBuffer()
  
  # Create PDU header
  var header = PDUHeader(
    version: 5,
    minorVersion: 0,
    pType: ptRequest,  # REQUEST
    pFlags: 3,  # FIRST_FRAG | LAST_FRAG
    drep: [0x10'u8, 0, 0, 0],  # Little-endian
    fragLength: 0,  # Will be updated
    authLength: 0,
    callId: 2
  )
  
  encodePDUHeader(buf, header)
  
  # PDU Request fields
  encodeUint32(buf, 0x70)  # allocHint
  encodeUint16(buf, 1)      # contextID
  encodeUint16(buf, 0x0F)   # opNum (NetrShareEnum)
  
  let servername = r"\\" & client.host
  let wideStr = servername.toUtf16LE() & @[0'u8, 0]  # Add null terminator
  let charCount = (wideStr.len div 2).uint32
  
  # Server name parameter - NDR64 inline string with pointer semantics
  encodePointerNDR64(buf, 0x00020000)  # Pointer referent
  encodeUint32NDR64(buf, charCount)     # MaxCount with padding
  encodeUint32NDR64(buf, 0)             # Offset with padding
  encodeUint32NDR64(buf, charCount)     # ActualCount with padding
  
  # Server name string data
  for b in wideStr:
    encodeUint8(buf, b)
  
  # Level and share info structure
  encodeUint32NDR64(buf, 1)            # Level = 1
  encodeUint32NDR64(buf, 1)            # Union discriminant = 1
  encodeUint32(buf, 0x00020000)        # InfoStruct pointer referent
  encodeUint32(buf, 0)                 # EntriesRead = 0
  encodeUint32NDR64(buf, 0)            # Buffer pointer = NULL
  
  # Max Buffer
  encodeUint32NDR64(buf, 0)            # PrefMaxLen = 0
  
  # Resume Handle
  encodeUint32NDR64(buf, 0xFFFFFFFF'u32)   # Resume handle referent or value
  encodeUint32NDR64(buf, 0)            # Resume handle value
  
  # Update fragLength
  let totalLen = buf.position.uint16
  buf.data[8] = uint8(totalLen and 0xFF)
  buf.data[9] = uint8((totalLen shr 8) and 0xFF)
  
  # Debug output
  #echo fmt"RPC Request ({buf.position} bytes):"
  #for i in 0..<buf.position:
  #  stdout.write(fmt"{buf.data[i]:02x} ")
  #  if (i + 1) mod 16 == 0:
  #    echo ""
  #if buf.position mod 16 != 0:
  #  echo ""
  
  # Send IOCTL
  var ioctlReq = client.newIoctlRequest()
  ioctlReq.request.ctlCode = 0x0011C017
  ioctlReq.request.inputCount = buf.position.uint32
  ioctlReq.request.flags = 1
  ioctlReq.data = buf.data[0..<buf.position]
  copyMem(ioctlReq.request.fileID[0].addr, fileId.persistent.addr, sizeof(fileId.persistent))
  copyMem(ioctlReq.request.fileID[8].addr, fileId.volatile.addr, sizeof(fileId.volatile))
  
  let ioctlReqBytes = ioctlReq.build()
  let (ioctlRes, ioctlResStatus) = client.send(ioctlReqBytes)
  
  if ioctlResStatus == 0:
    result = ioctlRes
  else:
    echo "[-] Server Returned Error 0x", toHex(ioctlResStatus)
  
  return result

proc listShares*(client: SmbClient): seq[ShareInfo1] =
  #result = @[]
  var fileId: tuple[persistent, volatile: uint64]
  let bindSrvsvc = newSrvSvcRPCBind()
  var netShareEnumRes: seq[uint8]
  try:
    # Connect to IPC$
    client.connectToShare("IPC$")
    # Open SRVSVC pipe
    fileId = client.openNamedPipe("srvsvc")
    echo "\n[+] Opened pipe to SRVSVC!"
    # Bind to SRVSVC interface
    if not client.bindRPC(fileId, bindSrvsvc): return
    
    # Read from SRVSVC pipe for Bind Acknowledgement Response
    if not client.readBindAck(fileId):
        echo "\n[-] Did Not Receive Bind Acknowledgement From Server!"
        return @[]
    
    netShareEnumRes = client.sendNetShareEnumAll(fileId) # Send NetShareEnum request
    if netShareEnumRes.len == 0:
      echo "\n[-] Failed to Retrieve Share List!"
    else: 
      result = parseShares(netShareEnumRes)
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
