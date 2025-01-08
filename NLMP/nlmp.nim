from std/sysrand import urandom
from ../utils/utils import toUtf16LE

import std/[endians, strutils, times]
import hashlib/rhash/[md4, md5]

const
    # NTLM flags without signing
  NTLM_NEGOTIATE_UNICODE* = 0x00000001'u32 # 0x05 bit 0
  NTLM_NEGOTIATE_NTLM* = 0x00000200'u32
  NTLM_REQUEST_TARGET* = 0x00000004'u32 # 0x08 bit 2
  NTLM_NEGOTIATE_128* = 0x20000000'u32 # 0xA0 bit 7
  NTLM_NEGOTIATE_VERSION* = 0x02000000'u32 # 0xA0 bit 5
  NTLM_NEGOTIATE_EXTENDED_SESSIONSECURITY* = 0x00080000'u32 # 0x80 bit 7
  NTLM_NEGOTIATE_OEM* = 0x00000002'u32 # 0x05 bit 1

type
  AVPairType* = enum
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

  AVPair* = object
   avId*: uint16
   avLen*: uint16
   avValue*: seq[uint8]

  NTLMNegoMsg* {.packed.} = object
    messageType*: uint32
    flags*: uint32
    domainNameLength*: uint16
    domainNameMaxLen*: uint16
    domainNameOffset*: uint32
    workstationNameLength*: uint16
    workstationNameMaxLen*: uint16
    workstationNameOffset*: uint32
    majorVersionNumber*: uint8
    minorVersionNumber*: uint8
    buildNumber*: uint16
    reserved*: array[3, uint8]
    revision*: uint8
  
  NTLMAuthMsg* = object
    signature*: array[8, uint8]
    messageType*: uint32
    lmChallengeResponseLen*: uint16
    lmChallengeResponseMaxLen*: uint16
    lmChallengeResponseBufferOffset*: uint32
    ntChallengeResponseLen*: uint16
    ntChallengeResponseMaxLen*: uint16
    ntChallengeResponseBufferOffset*: uint32
    domainNameLen*: uint16
    domainNameMaxLen*: uint16
    domainNameBufferOffset*: uint32
    userNameLen*: uint16
    userNameMaxLen*: uint16
    userNameBufferOffset*: uint32
    workstationLen*: uint16
    workstationMaxLen*: uint16
    workstationBufferOffset*: uint32
    encryptedRandomSessionKeyLen*: uint16
    encryptedRandomSessionKeyMaxLen*: uint16
    encryptedRandomSessionKeyBufferOffset*: uint32
    flags*: uint32
    majorVersionNumber*: uint8
    minorVersionNumber*: uint8
    buildNumber*: uint16
    reserved*: array[3, uint8]
    revision*: uint8
    mic*: array[16, uint8]
  
  NTLMv2RESPONSE* = object
    response*: array[16, uint8]
    ntlmv2ClientChallenge*: seq[uint8]
    

proc generateNTLMHash*(password: string): string =
  # Convert password to UTF-16LE
  let utf16password = toUtf16LE(password)
  
  # Use the stream API for MD4
  var ctx = init[RHASH_MD4]()
  ctx.update(utf16password)
  let hash = ctx.final()
  
  # Convert to uppercase hex string
  result = ($hash).toUpperAscii()
  
proc parseNTLMChallengeMsg*(securityBlob: seq[uint8]): tuple[serverChallenge: array[8, uint8], targetName: seq[uint8], targetInfo: seq[uint8]] =
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

proc parseTargetInfo*(targetInfo: seq[uint8]): seq[AVPair] =
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

proc createClientChallenge*(avPairs: seq[AVPair], timestamp: uint64): seq[uint8] =
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

proc calculateNTLMv2Response*(ntlmHash: string, username: string, targetName: string, serverChallenge: array[8, uint8], targetInfo: seq[uint8]): NTLMv2RESPONSE =
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

proc createNTLMMsg*(msgType: int, pNTLMStateNegoFlags: ptr uint32 = nil, username: string = "", targetName: seq[uint8] = @[], ntlmv2Resp: NTLMv2RESPONSE = NTLMv2RESPONSE()): seq[uint8] =
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
    #echo "NTLM Msg Length: ", ntlmMsg.len
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
