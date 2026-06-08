## ntlm/messages.nim — NEGOTIATE / CHALLENGE / AUTHENTICATE wire format.
##
## MS-NLMP §2.2.1.{1,2,3} message structures. Each message starts with
## the 8-byte signature ``"NTLMSSP\0"`` then a 32-bit MessageType.
##
## "Fields" entries (DomainNameFields, etc.) are 8-byte triples on the
## wire: Length u16, MaxLength u16, BufferOffset u32. The actual bytes
## live in the message's payload area at ``BufferOffset`` from the start
## of the message.
##
## NEGOTIATE flag constants are from MS-NLMP §2.2.2.5.

import ../../common/[buffers, endian, unicode]

{.push warning[HoleEnumConv]: off.}

const NtlmSignature* = "NTLMSSP\0"
const NtlmSignatureBytes*: array[8, byte] =
  [byte('N'), byte('T'), byte('L'), byte('M'),
   byte('S'), byte('S'), byte('P'), 0'u8]

proc toBytes(s: string): seq[byte] =
  result = newSeq[byte](s.len)
  for i, ch in s: result[i] = byte(ch.ord)

proc fromBytes(b: openArray[byte]): string =
  result = newString(b.len)
  for i, x in b: result[i] = char(x)

type
  NtlmFlag* {.size: 4.} = enum
    NEGOTIATE_UNICODE             = 0
    NEGOTIATE_OEM                 = 1
    REQUEST_TARGET                = 2
    # bit 3 reserved
    NEGOTIATE_SIGN                = 4
    NEGOTIATE_SEAL                = 5
    NEGOTIATE_DATAGRAM            = 6
    NEGOTIATE_LM_KEY              = 7
    # bit 8 reserved
    NEGOTIATE_NTLM                = 9
    # bit 10 reserved
    NEGOTIATE_ANONYMOUS           = 11
    NEGOTIATE_OEM_DOMAIN_SUPPLIED = 12
    NEGOTIATE_OEM_WORKSTATION_SUPPLIED = 13
    # bit 14 reserved
    NEGOTIATE_ALWAYS_SIGN         = 15
    TARGET_TYPE_DOMAIN            = 16
    TARGET_TYPE_SERVER            = 17
    # bit 18 reserved
    NEGOTIATE_EXTENDED_SESSIONSECURITY = 19
    NEGOTIATE_IDENTIFY            = 20
    # bit 21 reserved
    REQUEST_NON_NT_SESSION_KEY    = 22
    NEGOTIATE_TARGET_INFO         = 23
    # bit 24 reserved
    NEGOTIATE_VERSION             = 25
    # bits 26..27 reserved
    NEGOTIATE_128                 = 29
    NEGOTIATE_KEY_EXCH            = 30
    NEGOTIATE_56                  = 31

  NtlmFlags* = set[NtlmFlag]

# --- flag encoding --------------------------------------------------------

proc toU32*(f: NtlmFlags): uint32 =
  for bit in f:
    result = result or (1'u32 shl ord(bit))

const ValidFlagBits = [0,1,2,4,5,6,7,9,11,12,13,15,16,17,19,20,22,23,25,29,30,31]

proc fromU32*(v: uint32): NtlmFlags =
  for i in ValidFlagBits:
    if (v and (1'u32 shl i)) != 0:
      result.incl NtlmFlag(i)

# --- AV_PAIR (target info) ------------------------------------------------

type
  AvId* = enum
    MsvAvEOL          = 0
    MsvAvNbComputer   = 1
    MsvAvNbDomain     = 2
    MsvAvDnsComputer  = 3
    MsvAvDnsDomain    = 4
    MsvAvDnsTree      = 5
    MsvAvFlags        = 6
    MsvAvTimestamp    = 7
    MsvAvSingleHost   = 8
    MsvAvTargetName   = 9
    MsvAvChannelBindings = 10

  AvPair* = object
    id*: AvId
    value*: seq[byte]

proc serialize*(pairs: openArray[AvPair]; addEol = true): seq[byte] =
  let b = newBuffer()
  for p in pairs:
    b.writeU16LE(uint16(ord(p.id)))
    b.writeU16LE(uint16(p.value.len))
    b.writeBytes(p.value)
  if addEol:
    b.writeU16LE(uint16(ord(MsvAvEOL)))
    b.writeU16LE(0)
  result = b.consumed

proc parseAvPairs*(data: openArray[byte]): seq[AvPair] =
  let b = newBuffer(data)
  while b.remaining >= 4:
    let id = b.readU16LE()
    let l  = b.readU16LE()
    if id == uint16(ord(MsvAvEOL)) and l == 0: break
    let bytes = b.readBytes(int(l))
    result.add AvPair(id: AvId(id), value: bytes)

# --- common Fields triple ------------------------------------------------

type
  Fields* = object
    length*: uint16
    maxLength*: uint16
    offset*: uint32

proc writeFields*(b: Buffer; f: Fields) =
  b.writeU16LE(f.length)
  b.writeU16LE(f.maxLength)
  b.writeU32LE(f.offset)

proc readFields*(b: Buffer): Fields =
  result.length = b.readU16LE()
  result.maxLength = b.readU16LE()
  result.offset = b.readU32LE()

# --- Version (MS-NLMP §2.2.2.10) ----------------------------------------

type
  NtlmVersion* = object
    productMajor*, productMinor*: uint8
    productBuild*: uint16
    ntlmRevision*: uint8

const DefaultVersion* = NtlmVersion(
  productMajor: 6, productMinor: 1,
  productBuild: 7600, ntlmRevision: 15)  # Windows 7-ish, NTLMSSP_REVISION_W2K3 = 15

proc writeVersion*(b: Buffer; v: NtlmVersion) =
  b.writeByte(v.productMajor)
  b.writeByte(v.productMinor)
  b.writeU16LE(v.productBuild)
  b.writeByte(0); b.writeByte(0); b.writeByte(0)  # reserved (3 bytes)
  b.writeByte(v.ntlmRevision)

proc readVersion*(b: Buffer): NtlmVersion =
  result.productMajor = b.readByte()
  result.productMinor = b.readByte()
  result.productBuild = b.readU16LE()
  discard b.readBytes(3)
  result.ntlmRevision = b.readByte()

# --- NEGOTIATE_MESSAGE (Type 1) -----------------------------------------

type
  NegotiateMessage* = object
    flags*: NtlmFlags
    domain*: string         ## OEM (often empty)
    workstation*: string    ## OEM (often empty)
    version*: NtlmVersion
    hasVersion*: bool

proc build*(m: NegotiateMessage): seq[byte] =
  let b = newBuffer()
  b.writeBytes(@NtlmSignatureBytes)
  b.writeU32LE(1'u32)
  b.writeU32LE(toU32(m.flags))
  # Payload area starts after 32 (header+flags+two Fields triples) +
  # 8 (version) = 40 bytes when version present, else 32.
  let headerLen = if m.hasVersion: 40 else: 32
  let dom = toBytes(m.domain)
  let wks = toBytes(m.workstation)
  let domF = Fields(length: uint16(dom.len), maxLength: uint16(dom.len),
                    offset: uint32(headerLen))
  let wksF = Fields(length: uint16(wks.len), maxLength: uint16(wks.len),
                    offset: uint32(headerLen + dom.len))
  b.writeFields(domF)
  b.writeFields(wksF)
  if m.hasVersion: b.writeVersion(m.version)
  b.writeBytes(dom)
  b.writeBytes(wks)
  result = b.consumed

proc parseNegotiate*(data: openArray[byte]): NegotiateMessage =
  let b = newBuffer(data)
  if fromBytes(b.readBytes(8)) != NtlmSignature:
    raise newException(ValueError, "not an NTLM message")
  let mtype = b.readU32LE()
  if mtype != 1: raise newException(ValueError, "not a NEGOTIATE message")
  result.flags = fromU32(b.readU32LE())
  let domF = b.readFields()
  let wksF = b.readFields()
  result.hasVersion = NEGOTIATE_VERSION in result.flags
  if result.hasVersion:
    result.version = b.readVersion()
  if domF.length > 0:
    b.seek(int(domF.offset))
    result.domain = fromBytes(b.readBytes(int(domF.length)))
  if wksF.length > 0:
    b.seek(int(wksF.offset))
    result.workstation = fromBytes(b.readBytes(int(wksF.length)))

# --- CHALLENGE_MESSAGE (Type 2) -----------------------------------------

type
  ChallengeMessage* = object
    flags*: NtlmFlags
    targetName*: string             ## UTF-16LE on wire, decoded here
    serverChallenge*: array[8, byte]
    targetInfo*: seq[byte]          ## raw AV_PAIR blob
    version*: NtlmVersion
    hasVersion*: bool

proc build*(m: ChallengeMessage): seq[byte] =
  let b = newBuffer()
  let tnBytes = if NEGOTIATE_UNICODE in m.flags: toUtf16Bytes(m.targetName)
                else: toBytes(m.targetName)
  let ti = m.targetInfo
  b.writeBytes(@NtlmSignatureBytes)
  b.writeU32LE(2'u32)
  let headerLen = if m.hasVersion: 56 else: 48
  b.writeFields(Fields(length: uint16(tnBytes.len), maxLength: uint16(tnBytes.len),
                       offset: uint32(headerLen)))
  b.writeU32LE(toU32(m.flags))
  for x in m.serverChallenge: b.writeByte(x)
  for _ in 0 ..< 8: b.writeByte(0)   # Reserved
  b.writeFields(Fields(length: uint16(ti.len), maxLength: uint16(ti.len),
                       offset: uint32(headerLen + tnBytes.len)))
  if m.hasVersion: b.writeVersion(m.version)
  b.writeBytes(tnBytes)
  b.writeBytes(ti)
  result = b.consumed

proc parseChallenge*(data: openArray[byte]): ChallengeMessage =
  let b = newBuffer(data)
  if fromBytes(b.readBytes(8)) != NtlmSignature:
    raise newException(ValueError, "not an NTLM message")
  if b.readU32LE() != 2: raise newException(ValueError, "not a CHALLENGE message")
  let tnF = b.readFields()
  result.flags = fromU32(b.readU32LE())
  for i in 0 ..< 8: result.serverChallenge[i] = b.readByte()
  discard b.readBytes(8)
  let tiF = b.readFields()
  result.hasVersion = NEGOTIATE_VERSION in result.flags
  if result.hasVersion: result.version = b.readVersion()
  if tnF.length > 0:
    b.seek(int(tnF.offset))
    let raw = b.readBytes(int(tnF.length))
    result.targetName =
      if NEGOTIATE_UNICODE in result.flags: fromUtf16Bytes(raw)
      else: fromBytes(raw)
  if tiF.length > 0:
    b.seek(int(tiF.offset))
    result.targetInfo = b.readBytes(int(tiF.length))

# --- AUTHENTICATE_MESSAGE (Type 3) --------------------------------------

type
  AuthenticateMessage* = object
    flags*: NtlmFlags
    lmResponse*: seq[byte]
    ntResponse*: seq[byte]
    domain*: string                 ## UTF-16LE on wire if NEGOTIATE_UNICODE
    user*: string
    workstation*: string
    encryptedRandomSessionKey*: seq[byte]
    version*: NtlmVersion
    hasVersion*: bool
    mic*: array[16, byte]
    hasMic*: bool

proc build*(m: AuthenticateMessage): seq[byte] =
  let b = newBuffer()
  b.writeBytes(@NtlmSignatureBytes)
  b.writeU32LE(3'u32)

  let useUnicode = NEGOTIATE_UNICODE in m.flags
  let dom = if useUnicode: toUtf16Bytes(m.domain) else: toBytes(m.domain)
  let usr = if useUnicode: toUtf16Bytes(m.user)   else: toBytes(m.user)
  let wks = if useUnicode: toUtf16Bytes(m.workstation) else: toBytes(m.workstation)

  # Header size: 8 sig + 4 type + 6×8 Fields + 4 flags = 64
  # + 8 version (optional) + 16 MIC (optional)
  var headerLen = 64
  if m.hasVersion: headerLen += 8
  if m.hasMic: headerLen += 16

  var off = headerLen
  let lmF = Fields(length: uint16(m.lmResponse.len),
                   maxLength: uint16(m.lmResponse.len), offset: uint32(off))
  off += m.lmResponse.len
  let ntF = Fields(length: uint16(m.ntResponse.len),
                   maxLength: uint16(m.ntResponse.len), offset: uint32(off))
  off += m.ntResponse.len
  let domF = Fields(length: uint16(dom.len), maxLength: uint16(dom.len),
                    offset: uint32(off))
  off += dom.len
  let usrF = Fields(length: uint16(usr.len), maxLength: uint16(usr.len),
                    offset: uint32(off))
  off += usr.len
  let wksF = Fields(length: uint16(wks.len), maxLength: uint16(wks.len),
                    offset: uint32(off))
  off += wks.len
  let keyF = Fields(length: uint16(m.encryptedRandomSessionKey.len),
                    maxLength: uint16(m.encryptedRandomSessionKey.len),
                    offset: uint32(off))

  b.writeFields(lmF)
  b.writeFields(ntF)
  b.writeFields(domF)
  b.writeFields(usrF)
  b.writeFields(wksF)
  b.writeFields(keyF)
  b.writeU32LE(toU32(m.flags))
  if m.hasVersion: b.writeVersion(m.version)
  if m.hasMic:
    for x in m.mic: b.writeByte(x)
  b.writeBytes(m.lmResponse)
  b.writeBytes(m.ntResponse)
  b.writeBytes(dom)
  b.writeBytes(usr)
  b.writeBytes(wks)
  b.writeBytes(m.encryptedRandomSessionKey)
  result = b.consumed

proc parseAuthenticate*(data: openArray[byte]; hasMic = false): AuthenticateMessage =
  ## ``hasMic`` is signaled out-of-band (by the presence of an
  ## ``MsAvFlags`` AV_PAIR bit on the prior CHALLENGE). Callers that
  ## don't know should pass ``false``; the field positions are then
  ## interpreted without a MIC slot.
  let b = newBuffer(data)
  if fromBytes(b.readBytes(8)) != NtlmSignature:
    raise newException(ValueError, "not an NTLM message")
  if b.readU32LE() != 3:
    raise newException(ValueError, "not an AUTHENTICATE message")
  let lmF = b.readFields()
  let ntF = b.readFields()
  let domF = b.readFields()
  let usrF = b.readFields()
  let wksF = b.readFields()
  let keyF = b.readFields()
  result.flags = fromU32(b.readU32LE())
  result.hasVersion = NEGOTIATE_VERSION in result.flags
  if result.hasVersion: result.version = b.readVersion()
  result.hasMic = hasMic
  if hasMic:
    for i in 0 ..< 16: result.mic[i] = b.readByte()

  let useUnicode = NEGOTIATE_UNICODE in result.flags
  proc readField(field: Fields): seq[byte] =
    if field.length == 0: return @[]
    b.seek(int(field.offset))
    b.readBytes(int(field.length))

  result.lmResponse = readField(lmF)
  result.ntResponse = readField(ntF)
  result.domain = (if useUnicode: fromUtf16Bytes(readField(domF))
                   else: fromBytes(readField(domF)))
  result.user   = (if useUnicode: fromUtf16Bytes(readField(usrF))
                   else: fromBytes(readField(usrF)))
  result.workstation = (if useUnicode: fromUtf16Bytes(readField(wksF))
                         else: fromBytes(readField(wksF)))
  result.encryptedRandomSessionKey = readField(keyF)
{.pop.}
