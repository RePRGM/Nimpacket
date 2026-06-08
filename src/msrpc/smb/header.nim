## smb/header.nim — SMB2 packet header (MS-SMB2 §2.2.1.2).
##
## All SMB2 commands share a fixed 64-byte header (the "sync" variant —
## we don't deal with async transforms here). After the header comes a
## command-specific structure.

import ../common/[buffers, endian]

{.push warning[HoleEnumConv]: off.}

const SmbHeaderLen* = 64
const SmbSignature*: array[4, byte] = [0xFE'u8, byte('S'), byte('M'), byte('B')]

type
  Smb2Command* = enum
    cmdNegotiate     = 0x0000
    cmdSessionSetup  = 0x0001
    cmdLogoff        = 0x0002
    cmdTreeConnect   = 0x0003
    cmdTreeDisconnect = 0x0004
    cmdCreate        = 0x0005
    cmdClose         = 0x0006
    cmdRead          = 0x0008
    cmdWrite         = 0x0009
    cmdIoctl         = 0x000B
    cmdEcho          = 0x000D

  Smb2Flag* = enum
    sfServerToRedir  = 0x00000001
    sfAsyncCommand   = 0x00000002
    sfRelatedOps     = 0x00000004
    sfSigned         = 0x00000008

  Smb2Header* = object
    creditCharge*: uint16
    status*: uint32
    command*: Smb2Command
    creditsRequested*: uint16
    flags*: uint32
    nextCommand*: uint32
    messageId*: uint64
    treeId*: uint32
    sessionId*: uint64
    signature*: array[16, byte]

proc writeHeader*(b: Buffer; h: Smb2Header) =
  b.writeBytes(SmbSignature)
  b.writeU16LE(64)                  # StructureSize (always 64)
  b.writeU16LE(h.creditCharge)
  b.writeU32LE(h.status)
  b.writeU16LE(uint16(ord(h.command)))
  b.writeU16LE(h.creditsRequested)
  b.writeU32LE(h.flags)
  b.writeU32LE(h.nextCommand)
  b.writeU64LE(h.messageId)
  b.writeU32LE(0xFEFF)              # Reserved / process id high (per spec)
  b.writeU32LE(h.treeId)
  b.writeU64LE(h.sessionId)
  for x in h.signature: b.writeByte(x)

proc readHeader*(b: Buffer): Smb2Header =
  let sig = b.readBytes(4)
  doAssert sig == @SmbSignature, "not an SMB2 packet"
  discard b.readU16LE()             # StructureSize
  result.creditCharge = b.readU16LE()
  result.status = b.readU32LE()
  result.command = Smb2Command(b.readU16LE())
  result.creditsRequested = b.readU16LE()
  result.flags = b.readU32LE()
  result.nextCommand = b.readU32LE()
  result.messageId = b.readU64LE()
  discard b.readU32LE()             # Reserved
  result.treeId = b.readU32LE()
  result.sessionId = b.readU64LE()
  for i in 0 ..< 16:
    result.signature[i] = b.readByte()
{.pop.}
