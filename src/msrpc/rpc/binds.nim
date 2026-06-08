## rpc/bind.nim — bind, bind_ack, bind_nak (C706 §12.6.4).
##
## Layout of a BIND PDU after the standard 16-byte header:
##
##   max_xmit_frag  u16
##   max_recv_frag  u16
##   assoc_group_id u32
##   p_context_elem (presentation context list)
##     n_context_elem u8
##     reserved       u8
##     reserved2      u16
##     contexts       [n] PresentationContext
##
## Each PresentationContext is:
##   p_cont_id              u16
##   n_transfer_syn         u8
##   reserved               u8
##   abstract_syntax        Syntax    (16-byte UUID + 4-byte version)
##   transfer_syntaxes      [n_transfer_syn] Syntax
##
## bind_ack mirrors this with a "result list" indicating, per context,
## whether the negotiation succeeded.

import ../common/[buffers, endian, guid]
import pdu

type
  SyntaxId* = object
    uuid*: Uuid
    version*: uint32    ## (minor << 16) | major   (C706 §12.6.4.4)

  PresentationContext* = object
    contextId*: uint16
    abstractSyntax*: SyntaxId
    transferSyntaxes*: seq[SyntaxId]

  PContextResult* = enum
    pcAcceptance        = 0
    pcUserRejection     = 1
    pcProviderRejection = 2

  PContextResultEntry* = object
    result*: PContextResult
    reason*: uint16
    transferSyntax*: SyntaxId

  BindPdu* = object
    maxXmit*, maxRecv*: uint16
    assocGroupId*: uint32
    contexts*: seq[PresentationContext]

  BindAckPdu* = object
    maxXmit*, maxRecv*: uint16
    assocGroupId*: uint32
    secondaryAddress*: string    ## ASCII, NUL-terminated on wire
    results*: seq[PContextResultEntry]

# --- well-known transfer syntaxes ---------------------------------------

const
  NdrTransferUuid* = "8a885d04-1ceb-11c9-9fe8-08002b104860"
  NdrTransferVer*  = 2'u16                              ## major
  # MS-RPCE NDR64
  Ndr64TransferUuid* = "71710533-beba-4937-8319-b5dbef9ccc36"
  Ndr64TransferVer*  = 1'u16
  # Bind-time feature negotiation (BTFN) — currently informational only
  BtfnUuid* = "6cb71c2c-9812-4540-0300-000000000000"

proc ndrTransferSyntax*(): SyntaxId =
  SyntaxId(uuid: parseUuid(NdrTransferUuid),
           version: uint32(NdrTransferVer))

proc ndr64TransferSyntax*(): SyntaxId =
  SyntaxId(uuid: parseUuid(Ndr64TransferUuid),
           version: uint32(Ndr64TransferVer))

# --- low-level Syntax helpers -------------------------------------------

proc writeSyntax*(b: Buffer; s: SyntaxId) =
  b.writeWire(s.uuid)
  b.writeU32LE(s.version)

proc readSyntax*(b: Buffer): SyntaxId =
  result.uuid = b.readWire()
  result.version = b.readU32LE()

# --- BIND ---------------------------------------------------------------

proc buildBindBody*(p: BindPdu): seq[byte] =
  let b = newBuffer()
  b.writeU16LE(p.maxXmit)
  b.writeU16LE(p.maxRecv)
  b.writeU32LE(p.assocGroupId)
  b.writeByte(uint8(p.contexts.len))
  b.writeByte(0)               # reserved
  b.writeU16LE(0)              # reserved2
  for c in p.contexts:
    b.writeU16LE(c.contextId)
    b.writeByte(uint8(c.transferSyntaxes.len))
    b.writeByte(0)             # reserved
    b.writeSyntax(c.abstractSyntax)
    for t in c.transferSyntaxes:
      b.writeSyntax(t)
  result = b.consumed

proc buildBind*(callId: uint32; p: BindPdu;
                maxXmit: uint16 = 5840; maxRecv: uint16 = 5840): seq[byte] =
  ## Returns a complete BIND PDU (header + body).
  var pp = p
  pp.maxXmit = maxXmit
  pp.maxRecv = maxRecv
  let body = buildBindBody(pp)
  var hdr = defaultHeader(ptBind, callId)
  hdr.fragLen = uint16(HeaderLen + body.len)
  let b = newBuffer()
  b.writeHeader(hdr)
  b.writeBytes(body)
  result = b.consumed

proc parseBindBody*(b: Buffer): BindPdu =
  result.maxXmit = b.readU16LE()
  result.maxRecv = b.readU16LE()
  result.assocGroupId = b.readU32LE()
  let n = int(b.readByte())
  discard b.readByte()
  discard b.readU16LE()
  for i in 0 ..< n:
    var c: PresentationContext
    c.contextId = b.readU16LE()
    let nts = int(b.readByte())
    discard b.readByte()
    c.abstractSyntax = b.readSyntax()
    for _ in 0 ..< nts:
      c.transferSyntaxes.add b.readSyntax()
    result.contexts.add c

# --- BIND_ACK -----------------------------------------------------------

proc buildBindAckBody*(p: BindAckPdu): seq[byte] =
  let b = newBuffer()
  b.writeU16LE(p.maxXmit)
  b.writeU16LE(p.maxRecv)
  b.writeU32LE(p.assocGroupId)

  # port_any: u16 length (incl NUL) then ASCII bytes then 4-byte align pad.
  let sec = p.secondaryAddress & "\0"
  b.writeU16LE(uint16(sec.len))
  for ch in sec: b.writeByte(byte(ch.ord))
  # Align to 4 bytes (relative to start of PDU = HeaderLen). The pad
  # depends on where the secondary address lands; the spec says align
  # the start of the result list to 4-byte boundary from the PDU start.
  while ((HeaderLen + b.pos) and 0x3) != 0:
    b.writeByte(0)

  b.writeByte(uint8(p.results.len))
  b.writeByte(0)              # reserved
  b.writeU16LE(0)             # reserved2
  for r in p.results:
    b.writeU16LE(uint16(ord(r.result)))
    b.writeU16LE(r.reason)
    b.writeSyntax(r.transferSyntax)
  result = b.consumed

proc buildBindAck*(callId: uint32; p: BindAckPdu): seq[byte] =
  let body = buildBindAckBody(p)
  var hdr = defaultHeader(ptBindAck, callId)
  hdr.fragLen = uint16(HeaderLen + body.len)
  let b = newBuffer()
  b.writeHeader(hdr)
  b.writeBytes(body)
  result = b.consumed

proc parseBindAckBody*(b: Buffer): BindAckPdu =
  let bodyStart = b.pos
  result.maxXmit = b.readU16LE()
  result.maxRecv = b.readU16LE()
  result.assocGroupId = b.readU32LE()
  let secLen = int(b.readU16LE())
  if secLen > 0:
    let raw = b.readBytes(secLen)
    var s = ""
    for x in raw:
      if x == 0: break
      s.add char(x)
    result.secondaryAddress = s
  # Re-align to 4 bytes from start of PDU. ``bodyStart`` here is the
  # offset just after the 16-byte header inside this buffer.
  while ((HeaderLen + (b.pos - bodyStart)) and 0x3) != 0:
    discard b.readByte()
  let n = int(b.readByte())
  discard b.readByte()
  discard b.readU16LE()
  for i in 0 ..< n:
    var r: PContextResultEntry
    r.result = PContextResult(b.readU16LE())
    r.reason = b.readU16LE()
    r.transferSyntax = b.readSyntax()
    result.results.add r
