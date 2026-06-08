## smb/client.nim — minimum SMB2 client to access named pipes on IPC$.
##
## Goal: enough SMB2 to bring up a session, tree-connect IPC$, open a
## named pipe, and read/write bytes through it. Out of scope: SMB3
## encryption, signing (we use NTLM ESS sign-only at the session level
## but the per-message SMB signature is not validated by default
## Samba/Windows configurations against IPC$ for non-domain machines),
## directory traversal, leases, durable handles, multi-channel.
##
## The wire framing for SMB over TCP is "NetBIOS over TCP" style:
## ``0x00 || 24-bit BE length || message bytes`` (§2.1).

import std/[net, strutils]
import ../common/[buffers, endian, guid, unicode]
import ../auth/ntlm/provider
import header

type
  SmbError* = object of CatchableError

  SmbSession* = ref object
    sock*: Socket
    sessionId*: uint64
    treeId*: uint32
    messageId*: uint64
    serverGuid*: Uuid
    serverChallenge*: array[8, byte]
    provider*: NtlmProvider

  SmbPipe* = ref object
    session*: SmbSession
    fileId*: array[16, byte]

# --- transport framing ---------------------------------------------------

proc sendFrame(s: SmbSession; payload: openArray[byte]) =
  doAssert payload.len < 0x100_0000, "SMB frame too large"
  var hdr: array[4, byte]
  hdr[0] = 0
  hdr[1] = byte((payload.len shr 16) and 0xff)
  hdr[2] = byte((payload.len shr 8) and 0xff)
  hdr[3] = byte(payload.len and 0xff)
  var packet = newString(4 + payload.len)
  packet[0] = char(hdr[0]); packet[1] = char(hdr[1])
  packet[2] = char(hdr[2]); packet[3] = char(hdr[3])
  for i, b in payload: packet[4 + i] = char(b)
  s.sock.send(packet)

proc recvFrame(s: SmbSession): seq[byte] =
  var lenBuf = newString(4)
  if s.sock.recv(lenBuf, 4) != 4:
    raise newException(SmbError, "short read on SMB frame header")
  let n =
    (int(byte(lenBuf[1])) shl 16) or
    (int(byte(lenBuf[2])) shl 8) or
    int(byte(lenBuf[3]))
  result = newSeq[byte](n)
  var got = 0
  while got < n:
    var buf = newString(n - got)
    let m = s.sock.recv(buf, n - got)
    if m <= 0:
      raise newException(SmbError, "short read on SMB frame body")
    for i in 0 ..< m: result[got + i] = byte(buf[i].ord)
    got += m

# --- message helpers ----------------------------------------------------

proc nextMessageId(s: SmbSession): uint64 =
  result = s.messageId
  inc s.messageId

proc newHeader(s: SmbSession; cmd: Smb2Command): Smb2Header =
  Smb2Header(
    creditCharge: 1, command: cmd, creditsRequested: 64,
    flags: 0, messageId: s.nextMessageId(),
    treeId: s.treeId, sessionId: s.sessionId)

# --- NEGOTIATE (§2.2.3, §2.2.4) ---------------------------------------

proc negotiate(s: SmbSession) =
  let body = newBuffer()
  body.writeU16LE(36)                       # StructureSize
  body.writeU16LE(1)                        # DialectCount
  body.writeU16LE(0)                        # SecurityMode
  body.writeU16LE(0)                        # Reserved
  body.writeU32LE(0)                        # Capabilities
  for _ in 0 ..< 16: body.writeByte(0)      # ClientGuid (zeros for v1 of this code)
  body.writeU64LE(0)                        # ClientStartTime
  body.writeU16LE(0x0202)                   # Dialect SMB 2.0.2
  body.writeU16LE(0)                        # padding

  let hdrBuf = newBuffer()
  hdrBuf.writeHeader(s.newHeader(cmdNegotiate))
  hdrBuf.writeBytes(body.consumed)
  sendFrame(s, hdrBuf.consumed)

  let reply = recvFrame(s)
  let rb = newBuffer(reply)
  let respHdr = rb.readHeader()
  if respHdr.status != 0:
    raise newException(SmbError, "NEGOTIATE failed: 0x" & toHex(int64(respHdr.status), 8))
  discard rb.readU16LE()                    # StructureSize
  discard rb.readU16LE()                    # SecurityMode
  discard rb.readU16LE()                    # DialectRevision
  discard rb.readU16LE()                    # Reserved
  s.serverGuid = guid.readWire(rb)
  discard rb.readU32LE()                    # Capabilities
  discard rb.readU32LE()                    # MaxTransactSize
  discard rb.readU32LE()                    # MaxReadSize
  discard rb.readU32LE()                    # MaxWriteSize
  discard rb.readU64LE()                    # SystemTime
  discard rb.readU64LE()                    # ServerStartTime
  # The server's SecurityBuffer (the initial SPNEGO/NTLM token) follows
  # but we ignore it here — we'll send our own Type-1 NEGOTIATE.

# --- SESSION_SETUP (§2.2.5, §2.2.6) -----------------------------------

proc sessionSetup(s: SmbSession; targetSpn: string) =
  ## Two-trip NTLM session setup: send NTLMSSP_NEGOTIATE → receive
  ## CHALLENGE → send NTLMSSP_AUTHENTICATE. We skip the SPNEGO wrapping
  ## by sending bare NTLM tokens, which Samba and recent Windows accept
  ## when the dialect-2.0.2 spec doesn't require SPNEGO.
  let token1 = s.provider.initialize(targetSpn)

  proc sendSessionSetup(blob: openArray[byte]; sessionId = 0'u64): seq[byte] =
    let body = newBuffer()
    body.writeU16LE(25)                     # StructureSize
    body.writeByte(0)                       # Flags
    body.writeByte(0)                       # SecurityMode (1=signing enabled would be cleaner)
    body.writeU32LE(0)                      # Capabilities
    body.writeU32LE(0)                      # Channel
    body.writeU16LE(64 + 24)                # SecurityBufferOffset (header + body)
    body.writeU16LE(uint16(blob.len))       # SecurityBufferLength
    body.writeU64LE(0)                      # PreviousSessionId
    body.writeBytes(blob)

    let hb = newBuffer()
    var hdr = s.newHeader(cmdSessionSetup)
    hdr.sessionId = sessionId
    hb.writeHeader(hdr)
    hb.writeBytes(body.consumed)
    sendFrame(s, hb.consumed)
    result = recvFrame(s)

  let reply1 = sendSessionSetup(token1)
  let rb1 = newBuffer(reply1)
  let respHdr1 = rb1.readHeader()
  s.sessionId = respHdr1.sessionId
  if respHdr1.status != 0xC0000016'u32:    # STATUS_MORE_PROCESSING_REQUIRED
    raise newException(SmbError,
      "SESSION_SETUP step1 expected MORE_PROCESSING (0xC0000016), got 0x" &
      $respHdr1.status)
  discard rb1.readU16LE()                  # StructureSize
  discard rb1.readU16LE()                  # SessionFlags
  let secOff = rb1.readU16LE()
  let secLen = rb1.readU16LE()
  rb1.seek(int(secOff))
  let challenge = rb1.readBytes(int(secLen))

  let token2 = s.provider.step(challenge)
  let reply2 = sendSessionSetup(token2, s.sessionId)
  let rb2 = newBuffer(reply2)
  let respHdr2 = rb2.readHeader()
  if respHdr2.status != 0:
    raise newException(SmbError, "SESSION_SETUP step2 failed: 0x" & $respHdr2.status)

# --- TREE_CONNECT (§2.2.9, §2.2.10) -----------------------------------

proc treeConnect(s: SmbSession; host: string) =
  let path = "\\\\" & host & "\\IPC$"
  let pathBytes = toUtf16Bytes(path)
  let body = newBuffer()
  body.writeU16LE(9)                       # StructureSize
  body.writeU16LE(0)                       # Reserved
  body.writeU16LE(64 + 8)                  # PathOffset
  body.writeU16LE(uint16(pathBytes.len))   # PathLength
  body.writeBytes(pathBytes)

  let hb = newBuffer()
  hb.writeHeader(s.newHeader(cmdTreeConnect))
  hb.writeBytes(body.consumed)
  sendFrame(s, hb.consumed)

  let reply = recvFrame(s)
  let rb = newBuffer(reply)
  let respHdr = rb.readHeader()
  if respHdr.status != 0:
    raise newException(SmbError, "TREE_CONNECT failed: 0x" & toHex(int64(respHdr.status), 8))
  s.treeId = respHdr.treeId

# --- public connect / openPipe / read / write / close -----------------

proc newSmbSession*(host: string; port = 445; provider: NtlmProvider;
                    targetSpn = ""): SmbSession =
  result = SmbSession(provider: provider, messageId: 0,
                       treeId: 0, sessionId: 0)
  result.sock = newSocket(buffered = false)
  result.sock.connect(host, Port(port))
  let spn = if targetSpn.len > 0: targetSpn else: "cifs/" & host
  result.negotiate()
  result.sessionSetup(spn)
  result.treeConnect(host)

proc openPipe*(s: SmbSession; name: string): SmbPipe =
  ## MS-SMB2 §2.2.13: CREATE request.
  ## Static struct is 56 bytes; StructureSize must be 57 (one byte
  ## counted as the buffer placeholder). NameOffset is from the start
  ## of the SMB header (= 64 + 56 = 120). When CreateContexts are
  ## absent, leave the CreateContextsOffset / Length both zero.
  let fname = name.toUtf16Bytes()
  let body = newBuffer()
  body.writeU16LE(57)                       # StructureSize
  body.writeByte(0)                         # SecurityFlags
  body.writeByte(0)                         # RequestedOplockLevel
  body.writeU32LE(2)                        # ImpersonationLevel = Impersonation
  body.writeU64LE(0); body.writeU64LE(0)    # SmbCreateFlags / Reserved
  body.writeU32LE(0x0012019F)               # DesiredAccess: generic R/W on pipe
  body.writeU32LE(0)                        # FileAttributes
  body.writeU32LE(0x00000003)               # ShareAccess: read + write
  body.writeU32LE(1)                        # CreateDisposition: OPEN
  body.writeU32LE(0x40)                     # CreateOptions: FILE_NON_DIRECTORY_FILE
  body.writeU16LE(64 + 56)                  # NameOffset (header + static struct)
  body.writeU16LE(uint16(fname.len))        # NameLength
  body.writeU32LE(0)                        # CreateContextsOffset
  body.writeU32LE(0)                        # CreateContextsLength
  body.writeBytes(fname)                    # immediate file name (no leading pad needed)

  let hb = newBuffer()
  hb.writeHeader(s.newHeader(cmdCreate))
  hb.writeBytes(body.consumed)
  sendFrame(s, hb.consumed)

  let reply = recvFrame(s)
  let rb = newBuffer(reply)
  let respHdr = rb.readHeader()
  if respHdr.status != 0:
    raise newException(SmbError, "CREATE failed: 0x" & toHex(int64(respHdr.status), 8))
  discard rb.readU16LE()                    # StructureSize
  discard rb.readByte()                     # OplockLevel
  discard rb.readByte()                     # Flags
  discard rb.readU32LE()                    # CreateAction
  for _ in 0 ..< 8 * 4: discard rb.readByte()  # creation/access/write/change times
  for _ in 0 ..< 8 * 2: discard rb.readByte()  # alloc/end-of-file
  discard rb.readU32LE()                    # FileAttributes
  discard rb.readU32LE()                    # Reserved2
  result = SmbPipe(session: s)
  for i in 0 ..< 16: result.fileId[i] = rb.readByte()

proc write*(p: SmbPipe; data: openArray[byte]) =
  let body = newBuffer()
  body.writeU16LE(49)                       # StructureSize
  body.writeU16LE(64 + 48)                  # DataOffset
  body.writeU32LE(uint32(data.len))         # Length
  body.writeU64LE(0)                        # Offset
  for x in p.fileId: body.writeByte(x)      # FileId (16 bytes)
  body.writeU32LE(0)                        # Channel
  body.writeU32LE(0)                        # RemainingBytes
  body.writeU16LE(0)                        # WriteChannelInfoOffset
  body.writeU16LE(0)                        # WriteChannelInfoLength
  body.writeU32LE(0)                        # Flags
  body.writeBytes(data)

  let hb = newBuffer()
  hb.writeHeader(p.session.newHeader(cmdWrite))
  hb.writeBytes(body.consumed)
  sendFrame(p.session, hb.consumed)

  let reply = recvFrame(p.session)
  let rb = newBuffer(reply)
  let respHdr = rb.readHeader()
  if respHdr.status != 0:
    raise newException(SmbError, "WRITE failed: 0x" & toHex(int64(respHdr.status), 8))

proc read*(p: SmbPipe; n: int): seq[byte] =
  let body = newBuffer()
  body.writeU16LE(49)                       # StructureSize
  body.writeByte(0)                         # Padding
  body.writeByte(0)                         # Flags
  body.writeU32LE(uint32(n))                # Length
  body.writeU64LE(0)                        # Offset
  for x in p.fileId: body.writeByte(x)
  body.writeU32LE(uint32(n))                # MinimumCount
  body.writeU32LE(0)                        # Channel
  body.writeU32LE(0)                        # RemainingBytes
  body.writeU16LE(0)                        # ReadChannelInfoOffset
  body.writeU16LE(0)                        # ReadChannelInfoLength
  body.writeByte(0)                         # Buffer placeholder

  let hb = newBuffer()
  hb.writeHeader(p.session.newHeader(cmdRead))
  hb.writeBytes(body.consumed)
  sendFrame(p.session, hb.consumed)

  let reply = recvFrame(p.session)
  let rb = newBuffer(reply)
  let respHdr = rb.readHeader()
  if respHdr.status != 0:
    raise newException(SmbError, "READ failed: 0x" & toHex(int64(respHdr.status), 8))
  discard rb.readU16LE()                    # StructureSize
  let dataOff = rb.readByte()
  discard rb.readByte()                     # Reserved
  let dataLen = rb.readU32LE()
  discard rb.readU32LE()                    # DataRemaining
  discard rb.readU32LE()                    # Reserved2
  rb.seek(int(dataOff))
  result = rb.readBytes(int(dataLen))

const FSCTL_PIPE_TRANSCEIVE* = 0x0011C017'u32

proc transceive*(p: SmbPipe; data: openArray[byte];
                 maxOutput = 4280): seq[byte] =
  ## SMB2 IOCTL FSCTL_PIPE_TRANSCEIVE — the canonical RPC-over-named-
  ## pipe primitive on Windows. Sends ``data`` to the pipe and returns
  ## the server's response in a single round-trip.
  let body = newBuffer()
  body.writeU16LE(57)                       # StructureSize
  body.writeU16LE(0)                        # Reserved
  body.writeU32LE(FSCTL_PIPE_TRANSCEIVE)    # CtlCode
  for x in p.fileId: body.writeByte(x)      # FileId
  body.writeU32LE(64 + 56)                  # InputOffset (header + struct)
  body.writeU32LE(uint32(data.len))         # InputCount
  body.writeU32LE(0)                        # MaxInputResponse
  body.writeU32LE(0)                        # OutputOffset
  body.writeU32LE(0)                        # OutputCount
  body.writeU32LE(uint32(maxOutput))        # MaxOutputResponse
  body.writeU32LE(0x00000001)               # Flags: SMB2_0_IOCTL_IS_FSCTL
  body.writeU32LE(0)                        # Reserved2
  body.writeBytes(data)

  let hb = newBuffer()
  hb.writeHeader(p.session.newHeader(cmdIoctl))
  hb.writeBytes(body.consumed)
  sendFrame(p.session, hb.consumed)

  let reply = recvFrame(p.session)
  let rb = newBuffer(reply)
  let respHdr = rb.readHeader()
  # STATUS_BUFFER_OVERFLOW (0x80000005) is normal here — it just means
  # the server has more data; we'd need another READ to get the rest.
  # STATUS_PENDING (0x103) is normal for one-way PDUs (e.g. AUTH3): the
  # server acknowledged the request but produced no response payload.
  # For typical RPC responses that fit in maxOutput, status == 0.
  if respHdr.status != 0 and respHdr.status != 0x80000005'u32 and
     respHdr.status != 0x00000103'u32:
    raise newException(SmbError, "IOCTL TRANSCEIVE failed: 0x" & toHex(int64(respHdr.status), 8))
  # On STATUS_PENDING the response body is the SMB ERROR structure, not
  # the IOCTL response — return empty bytes without parsing further.
  if respHdr.status == 0x00000103'u32:
    return @[]
  discard rb.readU16LE()                    # StructureSize (49)
  discard rb.readU16LE()                    # Reserved
  discard rb.readU32LE()                    # CtlCode
  for _ in 0 ..< 16: discard rb.readByte()  # FileId
  discard rb.readU32LE()                    # InputOffset
  discard rb.readU32LE()                    # InputCount
  let outOff = rb.readU32LE()
  let outLen = rb.readU32LE()
  rb.seek(int(outOff))
  result = rb.readBytes(int(outLen))

proc close*(p: SmbPipe) =
  let body = newBuffer()
  body.writeU16LE(24)
  body.writeU16LE(0)
  body.writeU32LE(0)
  for x in p.fileId: body.writeByte(x)

  let hb = newBuffer()
  hb.writeHeader(p.session.newHeader(cmdClose))
  hb.writeBytes(body.consumed)
  sendFrame(p.session, hb.consumed)
  discard recvFrame(p.session)
