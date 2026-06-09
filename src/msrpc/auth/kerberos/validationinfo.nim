## validationinfo.nim — decode MS-PAC KERB_VALIDATION_INFO (logon info).
##
## This is the PAC buffer (type 1, ``PacLogonInfo``) that carries the user's
## identity: account name, the user and primary-group RIDs, the group RID
## list, and the logon-domain SID. It is NDR-marshalled using RPC "Type
## Serialization Version 1" — a 16-byte header, a top-level unique pointer to
## the struct, then the inline fields followed by the deferred pointer
## referents (conformant/varying arrays, embedded SID).
##
## Decode-only for now. Layout verified field-by-field against an
## impacket-generated golden blob; field order cross-checked against MS-PAC
## §2.5 and TrustedSec Titanis (ms-pac.cs).
##
## Limitation: a populated ``ExtraSids`` / resource-group list is not decoded
## yet (the golden vector has none). When those pointers are non-null the
## decoder stops after the logon-domain SID and leaves ``extraSidsPresent``
## set so callers know the tail was skipped.

import msrpc/common/buffers
import msrpc/common/endian
import msrpc/common/sid
import msrpc/common/unicode

type
  PacDecodeError* = object of CatchableError

  GroupMembership* = object
    relativeId*: uint32
    attributes*: uint32

  KerbValidationInfo* = object
    logonTime*, logoffTime*, kickOffTime*: uint64
    passwordLastSet*, passwordCanChange*, passwordMustChange*: uint64   ## FILETIMEs
    effectiveName*, fullName*, logonScript*: string
    profilePath*, homeDirectory*, homeDirectoryDrive*: string
    logonCount*, badPasswordCount*: uint16
    userId*, primaryGroupId*: uint32
    groups*: seq[GroupMembership]
    userFlags*: uint32
    logonServer*, logonDomainName*: string
    logonDomainId*: Sid
    hasLogonDomainId*: bool
    userAccountControl*: uint32
    sidCount*: uint32
    extraSidsPresent*: bool      ## true when ExtraSids was non-null (not decoded yet)

proc fail(msg: string) {.noreturn.} =
  raise newException(PacDecodeError, msg)

type UStrHeader = tuple[length, maxlen: uint16, refId: uint32]

proc readUStrHeader(b: Buffer): UStrHeader =
  result.length = b.readU16LE()
  result.maxlen = b.readU16LE()
  result.refId = b.readU32LE()

proc readStrReferent(b: Buffer): string =
  ## A deferred RPC_UNICODE_STRING buffer: MaxCount, Offset, ActualCount,
  ## then ActualCount UTF-16LE code units, padded to a 4-byte boundary.
  discard b.readU32LE()                 # MaxCount
  discard b.readU32LE()                 # Offset
  let actual = int(b.readU32LE())
  result = fromUtf16Bytes(b.readBytes(actual * 2))
  if result.len > 0 and result[^1] == '\0':
    result.setLen(result.len - 1)       # drop a trailing NUL if present
  let pad = (-b.pos) and 3              # NDR 4-byte alignment
  if pad > 0: discard b.readBytes(pad)

proc parseValidationInfo*(blob: openArray[byte]): KerbValidationInfo =
  ## Decode a KERB_VALIDATION_INFO (the bytes of a PAC ``PacLogonInfo`` buffer).
  ## Raises ``PacDecodeError`` on malformed input.
  let b = newBuffer(blob)
  try:
    # --- Type Serialization 1 header (16 bytes) ---
    let version = b.readU8()
    let endianness = b.readU8()
    discard b.readU16LE()                # CommonHeaderLength (8)
    discard b.readU32LE()                # filler 0xcccccccc
    if version != 1 or endianness != 0x10:
      fail("unsupported NDR type-serialization header (ver " & $version &
           ", endian 0x" & $endianness.int & ")")
    discard b.readU32LE()                # ObjectBufferLength
    discard b.readU32LE()                # private-header filler
    if b.readU32LE() == 0:               # top-level unique pointer referent id
      fail("null KERB_VALIDATION_INFO pointer")

    # --- inline struct (216 bytes) ---
    result.logonTime = b.readU64LE()
    result.logoffTime = b.readU64LE()
    result.kickOffTime = b.readU64LE()
    result.passwordLastSet = b.readU64LE()
    result.passwordCanChange = b.readU64LE()
    result.passwordMustChange = b.readU64LE()
    let effH = readUStrHeader(b)
    let fullH = readUStrHeader(b)
    let scriptH = readUStrHeader(b)
    let profileH = readUStrHeader(b)
    let homeH = readUStrHeader(b)
    let homeDriveH = readUStrHeader(b)
    result.logonCount = b.readU16LE()
    result.badPasswordCount = b.readU16LE()
    result.userId = b.readU32LE()
    result.primaryGroupId = b.readU32LE()
    let groupCount = int(b.readU32LE())
    let groupsRef = b.readU32LE()
    result.userFlags = b.readU32LE()
    discard b.readBytes(16)              # UserSessionKey
    let srvH = readUStrHeader(b)
    let domH = readUStrHeader(b)
    let domIdRef = b.readU32LE()
    discard b.readBytes(8)               # LMKey / Reserved1
    result.userAccountControl = b.readU32LE()
    discard b.readU32LE()                # SubAuthStatus
    discard b.readU64LE()                # LastSuccessfulILogon
    discard b.readU64LE()                # LastFailedILogon
    discard b.readU32LE()                # FailedILogonCount
    discard b.readU32LE()                # Reserved3
    result.sidCount = b.readU32LE()
    let extraSidsRef = b.readU32LE()
    let resGrpDomSidRef = b.readU32LE()
    discard b.readU32LE()                # ResourceGroupCount
    let resGrpIdsRef = b.readU32LE()

    # --- deferred referents, in pointer order ---
    if effH.refId != 0: result.effectiveName = readStrReferent(b)
    if fullH.refId != 0: result.fullName = readStrReferent(b)
    if scriptH.refId != 0: result.logonScript = readStrReferent(b)
    if profileH.refId != 0: result.profilePath = readStrReferent(b)
    if homeH.refId != 0: result.homeDirectory = readStrReferent(b)
    if homeDriveH.refId != 0: result.homeDirectoryDrive = readStrReferent(b)
    if groupsRef != 0:
      let mc = int(b.readU32LE())        # array MaxCount
      for _ in 0 ..< mc:
        var g: GroupMembership
        g.relativeId = b.readU32LE()
        g.attributes = b.readU32LE()
        result.groups.add g
    if srvH.refId != 0: result.logonServer = readStrReferent(b)
    if domH.refId != 0: result.logonDomainName = readStrReferent(b)
    if domIdRef != 0:
      discard b.readU32LE()              # conformant MaxCount (= sub-authority count)
      result.logonDomainId = readWire(b)
      result.hasLogonDomainId = true

    # Resource-group / ExtraSids tail is not decoded yet; flag if present.
    result.extraSidsPresent = extraSidsRef != 0 or resGrpDomSidRef != 0 or
                              resGrpIdsRef != 0
    if groupsRef != 0 and result.groups.len != groupCount:
      fail("GroupCount (" & $groupCount & ") disagrees with array (" &
           $result.groups.len & ")")
  except BufferRangeError as e:
    fail("truncated or malformed KERB_VALIDATION_INFO: " & e.msg)
