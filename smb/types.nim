from std/net import Socket, Port

const
  SMB2_MAGIC* = [0xFE'u8, 'S'.uint8, 'M'.uint8, 'B'.uint8]
  SMB2_HEADER_SIZE* = 64
  SMB2_IOCTL_RESP_HEADER_SIZE* = 48  # Size of IOCTL response header
  
  # SMB2 Commands
  SMB2_NEGOTIATE* = 0x0000'u16
  SMB2_SESSION_SETUP* = 0x0001'u16
  SMB2_TREE_CONNECT* = 0x0003'u16
  SMB2_TREE_DISCONNECT* = 0x0004'u16
  SMB2_CREATE* = 0x0005'u16
  SMB2_CLOSE* = 0x0006'u16
  SMB2_READ* = 0x0008'u16
  SMB2_WRITE* = 0x0009'u16
  SMB2_IOCTL* = 0x000B'u16

  # File Access Rights
  FILE_READ_DATA* = 0x00000001'u32
  FILE_WRITE_DATA* = 0x00000002'u32
  FILE_READ_EA* = 0x00000008'u32
  FILE_WRITE_EA* = 0x00000010'u32
  FILE_READ_ATTRIBUTES* = 0x00000080'u32
  FILE_WRITE_ATTRIBUTES* = 0x00000100'u32
  SYNCHRONIZE* = 0x00100000'u32

  # Share Access
  FILE_SHARE_READ* = 0x00000001'u32
  FILE_SHARE_WRITE* = 0x00000002'u32

type
  GSSAPI_Token* = object
    tokenType: uint32
    messageType: uint32
    length: uint32
    tokenData: seq[uint8]
    mechTypes: seq[uint8]
    mechTypesLength: uint32
    mechToken: seq[uint8]
    mechTokenLength: uint32

  SMB2Header* = object
    protocol*: array[4, uint8] = SMB2_MAGIC
    structureSize*: uint16 = 64
    creditCharge*: uint16 = 1
    status*: uint32 = 0
    command*: uint16
    credits*: uint16 = 1
    flags*: uint32 = 0
    nextCommand*: uint32 = 0
    messageId*: uint64 = 0
    processId*: uint32 = 0xFEFF
    treeId*: uint32 = 0
    sessionId*: uint64 = 0
    signature*: array[16, uint8] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
  
  SMB2SESSION_SETUP_REQUEST* {.packed.} = object
    structureSize*: uint16 = 25
    flags*: uint8 = 0
    securityMode*: uint8 = 1
    capabilities*: uint32 = 0
    channel*: uint32 = 0
    securityBufferOffset*: uint16 = 0
    securityBufferLength*: uint16 = 0
    previousSessionId*: uint64 = 0
  
  SMB2NegotiateRequest* {.packed.} = object
    structureSize*: uint16 = 36
    dialectCount*: uint16 = 2#2
    securityMode*: uint16 = 1
    reserved*: uint16 = 0
    capabilities*: uint32 = 0
    clientGUID*: array[16, uint8] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6]
    clientStartTime*: uint64 = 0
    dialects* = [0x0202'u16, 0x0210]
    # dialects (variable), padding (variable; optional), negotiateContextList (variable; SMB 3.1.1 only)
  
  SMB2CreateRequest* {.packed.} = object
    structureSize*: uint16 = 57
    securityFlags*: uint8 = 0
    requestedOplockLevel*: uint8 = 0
    impersonationLevel*: uint32 = 0
    smbCreateFlags*: uint64 = 0
    reserved*: uint64 = 0
    desiredAccess*: uint32 = 0
    fileAttributes*: uint32 = 0
    shareAccess*: uint32 = 0
    createDisposition*: uint32 = 0
    createOptions*: uint32 = 0
    nameOffset*: uint16 = 0
    nameLength*: uint16 = 0
    createContextsOffset*: uint32 = 0
    createContextsLength*: uint32 = 0

  SMB2WriteRequest* {.packed.} = object
    structureSize*: uint16 = 49
    dataOffset*: uint16 = 0
    length*: uint32 = 0
    offset*: uint64 = 0
    fileID*: array[16, uint8]
    channel*: uint32 = 0
    remainingBytes*: uint32 = 0
    writeChannelInfoOffset*: uint16 = 0
    writeChannelInfoLength*: uint16 = 0
    flags*: uint32 = 0

  SMB2ReadRequest* {.packed.} = object
    structureSize*: uint16 = 49
    padding*: uint8 = 0x50
    flags*: uint8 = 0
    length*: uint32 = 1024
    offset*: uint64 = 0
    fileID*: array[16, uint8]
    minimumCount*: uint32 = 0
    channel*: uint32 = 0
    remainingBytes*: uint32 = 0
    readChannelInfoOffset*: uint16 = 0
    readChannelInfoLength*: uint16 = 0

  SMB2IoctlRequest* {.packed.} = object
    structureSize*: uint16 = 57
    reserved*: uint16 = 0
    ctlCode*: uint32 = 0
    fileID*: array[16, uint8]
    inputOffset*: uint32 = 0x78
    inputCount*: uint32 = 0
    maxInputResponse*: uint32 = 0
    outputOffset*: uint32 = 0
    outputCount*: uint32 = 0
    maxOutputResponse*: uint32 = 1024
    flags*: uint32 = 0
    reserved2*: uint32 = 0

  SMB2TreeConnectRequest* {.packed.} = object
    structureSize*: uint16 = 9
    flags*: uint16 = 0
    pathOffset*: uint16 = 0
    pathLength*: uint16 = 0
 
  Share* = object
    name*: string
    description*: string

  NtlmState* = object
    username*: string
    domain*: string
    ntlmHash*: string
    negotiateFlags*: uint32

  SmbClient* = ref object
    socket*: Socket
    host*: string
    port*: Port
    connected*: bool
    sessionId*: uint64
    treeId*: uint32
    messageId*: uint64
    ntlmState*: NtlmState

  SMB2RequestBuilder*[T] {.packed.} = object
    header*: SMB2Header
    request*: T
    client*: SmbClient
    data*: seq[uint8]