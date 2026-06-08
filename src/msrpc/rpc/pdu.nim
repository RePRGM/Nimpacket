## rpc/pdu.nim — DCE-RPC / MS-RPCE PDU header.
##
## C706 §12.6, MS-RPCE §2.2.3. All connection-oriented PDUs start with
## the same 16-byte header below. The body that follows is type-specific
## and is handled by sibling modules (``bind``, ``request``, ``auth``).
##
##   rpc_vers       u8     5
##   rpc_vers_minor u8     0
##   PTYPE          u8     packet type (PduType)
##   pfc_flags      u8     PFC_* bitfield
##   packed_drep    [4]u8  data representation (0x10 0x00 0x00 0x00 for LE)
##   frag_length    u16    total PDU length on the wire
##   auth_length    u16    size of the security trailer (0 if none)
##   call_id        u32    per-call identifier
##
## Endianness on the wire is little-endian for everything we generate
## (DREP byte 0 == 0x10). We always accept LE on read, and surface BE
## via the DREP value if anyone needs it.

import ../common/[buffers, endian]

const RpcVersion* = 5'u8
const RpcVersionMinor* = 0'u8
const HeaderLen* = 16

type
  PduType* = enum
    ptRequest          = 0
    ptPing             = 1
    ptResponse         = 2
    ptFault            = 3
    ptWorking          = 4
    ptNocall           = 5
    ptReject           = 6
    ptAck              = 7
    ptClCancel         = 8
    ptFack             = 9
    ptCancelAck        = 10
    ptBind             = 11
    ptBindAck          = 12
    ptBindNak          = 13
    ptAlterContext     = 14
    ptAlterContextResp = 15
    ptAuth3            = 16
    ptShutdown         = 17
    ptCoCancel         = 18
    ptOrphaned         = 19

  PfcFlag* = enum
    pfcFirstFrag      = 0   ## first fragment
    pfcLastFrag       = 1   ## last fragment
    pfcPendingCancel  = 2   ## cancel was pending at sender
    pfcReserved3      = 3
    pfcConcurrentMpx  = 4
    pfcDidNotExecute  = 5   ## fault didn't execute
    pfcMaybe          = 6   ## "maybe" call semantics
    pfcObjectUuid     = 7   ## an object UUID follows the header

  PfcFlags* = set[PfcFlag]

  PduHeader* = object
    rpcVersion*: uint8
    rpcMinor*: uint8
    pType*: PduType
    flags*: PfcFlags
    dataRep*: array[4, byte]
    fragLen*: uint16
    authLen*: uint16
    callId*: uint32

const LittleEndianDrep*: array[4, byte] = [0x10'u8, 0x00, 0x00, 0x00]

proc defaultHeader*(pType: PduType; callId: uint32;
                    flags: PfcFlags = {pfcFirstFrag, pfcLastFrag}): PduHeader =
  PduHeader(
    rpcVersion: RpcVersion, rpcMinor: RpcVersionMinor,
    pType: pType, flags: flags, dataRep: LittleEndianDrep,
    fragLen: 0, authLen: 0, callId: callId)

proc flagsToByte*(f: PfcFlags): byte =
  for fl in f:
    result = result or byte(1'u8 shl ord(fl))

proc flagsFromByte*(v: byte): PfcFlags =
  for i in 0 ..< 8:
    if (v and byte(1'u8 shl i)) != 0:
      result.incl PfcFlag(i)

proc writeHeader*(b: Buffer; h: PduHeader) =
  b.writeByte(h.rpcVersion)
  b.writeByte(h.rpcMinor)
  b.writeByte(byte(ord(h.pType)))
  b.writeByte(flagsToByte(h.flags))
  for x in h.dataRep: b.writeByte(x)
  b.writeU16LE(h.fragLen)
  b.writeU16LE(h.authLen)
  b.writeU32LE(h.callId)

proc readHeader*(b: Buffer): PduHeader =
  result.rpcVersion = b.readByte()
  result.rpcMinor   = b.readByte()
  let pt = b.readByte()
  if int(pt) > ord(PduType.high):
    raise newException(ValueError, "unknown PDU type: " & $pt)
  result.pType      = PduType(pt)
  result.flags      = flagsFromByte(b.readByte())
  for i in 0 ..< 4: result.dataRep[i] = b.readByte()
  result.fragLen = b.readU16LE()
  result.authLen = b.readU16LE()
  result.callId  = b.readU32LE()

proc isLittleEndian*(h: PduHeader): bool {.inline.} =
  (h.dataRep[0] and 0xf0'u8) == 0x10'u8
