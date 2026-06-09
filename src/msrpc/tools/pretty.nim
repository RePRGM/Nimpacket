## tools/pretty.nim — wire-format pretty-printer.
##
## Take a blob of bytes and decode it as one of the protocols we know
## (SMB2 PDU, DCE-RPC PDU, NTLMSSP message, Kerberos token, LDAP message).
## Auto-detects from a magic-byte sniff; callers can also force the
## protocol if they have ambiguous bytes.
##
## Designed for terminal output. One field per line, byte offsets at
## the left, field name in the middle, decoded value on the right.

import std/[strutils, strformat]
import ../common/buffers
import ../rpc/pdu
import ../smb/header as smbHeader
import ../auth/ntlm/messages as ntlmMessages

type
  Protocol* = enum
    pAuto = "auto"
    pSmb2 = "smb2"
    pRpc  = "dce-rpc"
    pNtlm = "ntlmssp"
    pKrb  = "kerberos"
    pLdap = "ldap"
    pUnknown = "unknown"

  PrettyLine* = object
    offset*: int
    name*: string
    value*: string
    note*: string         ## optional commentary

# --- format helpers -----------------------------------------------

proc hexByte*(b: byte): string = toHex(int(b), 2).toLowerAscii

proc hex*(d: openArray[byte]; maxLen = 32): string =
  let n = min(d.len, maxLen)
  for i in 0 ..< n:
    if i > 0 and (i mod 4) == 0: result.add ' '
    result.add hexByte(d[i])
  if d.len > maxLen: result.add fmt" …(+{d.len - maxLen})"

proc ascii*(d: openArray[byte]; maxLen = 64): string =
  let n = min(d.len, maxLen)
  for i in 0 ..< n:
    let c = char(d[i])
    result.add (if c.ord in 32..126: c else: '.')

proc formatLines*(lines: openArray[PrettyLine]): string =
  ## Render lines as "offset  name  value  # note".
  var nameW = 0
  var valW  = 0
  for l in lines:
    if l.name.len > nameW: nameW = l.name.len
    if l.value.len > valW: valW = l.value.len
  for l in lines:
    let pad = "  "
    result.add fmt"0x{l.offset:04x}{pad}"
    result.add l.name
    for _ in 0 ..< nameW - l.name.len: result.add ' '
    result.add pad
    result.add l.value
    if l.note.len > 0:
      for _ in 0 ..< valW - l.value.len: result.add ' '
      result.add "  # "
      result.add l.note
    result.add '\n'

# --- protocol sniffer --------------------------------------------

proc sniffProtocol*(d: openArray[byte]): Protocol =
  if d.len < 4: return pUnknown
  # SMB2: \xFE 'S' 'M' 'B'
  if d[0] == 0xFE'u8 and d[1] == byte('S') and
     d[2] == byte('M') and d[3] == byte('B'): return pSmb2
  # SMB3 TRANSFORM: \xFD 'S' 'M' 'B'
  if d[0] == 0xFD'u8 and d[1] == byte('S') and
     d[2] == byte('M') and d[3] == byte('B'): return pSmb2
  # NTLMSSP: "NTLMSSP\0"
  if d.len >= 8 and d[0] == byte('N') and d[1] == byte('T') and
     d[2] == byte('L') and d[3] == byte('M') and
     d[4] == byte('S') and d[5] == byte('S') and
     d[6] == byte('P') and d[7] == 0'u8: return pNtlm
  # DCE-RPC: version 5 + reasonable PTYPE + LE DREP
  if d.len >= 8 and d[0] == 5'u8 and d[1] == 0'u8 and
     int(d[2]) <= 19 and (d[4] and 0xf0'u8) == 0x10'u8: return pRpc
  # Kerberos: [APPLICATION n] outer tags
  if d[0] in {0x6A'u8, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F, 0x7E}: return pKrb
  # LDAP outer SEQUENCE
  if d[0] == 0x30'u8: return pLdap
  pUnknown

# --- SMB2 ---------------------------------------------------------

const Smb2CmdNames = [
  "NEGOTIATE", "SESSION_SETUP", "LOGOFF", "TREE_CONNECT",
  "TREE_DISCONNECT", "CREATE", "CLOSE", "FLUSH",
  "READ", "WRITE", "LOCK", "IOCTL",
  "CANCEL", "ECHO", "QUERY_DIRECTORY", "CHANGE_NOTIFY",
  "QUERY_INFO", "SET_INFO", "OPLOCK_BREAK"]

proc cmdName(c: uint16): string =
  if int(c) < Smb2CmdNames.len: Smb2CmdNames[c]
  else: "(unknown 0x" & toHex(int(c), 4) & ")"

proc prettySmb2*(d: openArray[byte]): seq[PrettyLine] =
  if d.len < 4: return
  # Transform header (encrypted)?
  if d[0] == 0xFD'u8:
    result.add PrettyLine(offset: 0, name: "ProtocolId",
                           value: "\\xFDSMB",
                           note: "SMB3 TRANSFORM (encrypted)")
    if d.len >= 52:
      result.add PrettyLine(offset: 4, name: "Signature",
                             value: hex(d[4 ..< 20]))
      result.add PrettyLine(offset: 20, name: "Nonce",
                             value: hex(d[20 ..< 36]))
      let osz = uint32(d[36]) or (uint32(d[37]) shl 8) or
                (uint32(d[38]) shl 16) or (uint32(d[39]) shl 24)
      result.add PrettyLine(offset: 36, name: "OriginalSize",
                             value: $osz)
      let flags = uint16(d[42]) or (uint16(d[43]) shl 8)
      result.add PrettyLine(offset: 42, name: "Flags",
                             value: "0x" & toHex(int(flags), 4),
                             note:
        if (flags and 1'u16) != 0: "encryption algorithm 1 (AES-CCM)" else: "")
    return

  if d.len < 64:
    result.add PrettyLine(offset: 0, name: "(truncated)",
                           value: hex(d))
    return
  let b = newBuffer(@d)
  let h = smbHeader.readHeader(b)
  result.add PrettyLine(offset: 0, name: "ProtocolId", value: "\\xFESMB")
  result.add PrettyLine(offset: 4, name: "StructureSize", value: "64")
  result.add PrettyLine(offset: 6, name: "CreditCharge",
                         value: $h.creditCharge)
  result.add PrettyLine(offset: 8, name: "Status",
                         value: "0x" & toHex(int64(h.status), 8))
  result.add PrettyLine(offset: 12, name: "Command",
                         value: cmdName(uint16(ord(h.command))),
                         note: "0x" & toHex(ord(h.command), 4))
  result.add PrettyLine(offset: 14, name: "CreditsRequested",
                         value: $h.creditsRequested)
  result.add PrettyLine(offset: 16, name: "Flags",
                         value: "0x" & toHex(int64(h.flags), 8),
                         note:
    if (h.flags and 1'u32) != 0: "ServerToRedir " else: "" &
    (if (h.flags and 2'u32) != 0: "Async " else: "") &
    (if (h.flags and 4'u32) != 0: "Related " else: "") &
    (if (h.flags and 8'u32) != 0: "Signed " else: ""))
  result.add PrettyLine(offset: 20, name: "NextCommand",
                         value: $h.nextCommand)
  result.add PrettyLine(offset: 24, name: "MessageId",
                         value: $h.messageId)
  result.add PrettyLine(offset: 36, name: "TreeId",
                         value: "0x" & toHex(int64(h.treeId), 8))
  result.add PrettyLine(offset: 40, name: "SessionId",
                         value: "0x" & toHex(int64(h.sessionId), 16))
  result.add PrettyLine(offset: 48, name: "Signature",
                         value: hex(h.signature),
                         note:
    if (h.flags and 8'u32) != 0: "" else: "(unsigned PDU; ignored)")
  if d.len > 64:
    result.add PrettyLine(offset: 64, name: "Body",
                           value: hex(d[64 ..< d.len], maxLen = 48))

# --- DCE-RPC ------------------------------------------------------

const PduTypeNames = [
  "REQUEST", "PING", "RESPONSE", "FAULT", "WORKING",
  "NOCALL", "REJECT", "ACK", "CL_CANCEL", "FACK",
  "CANCEL_ACK", "BIND", "BIND_ACK", "BIND_NAK",
  "ALTER_CONTEXT", "ALTER_CONTEXT_RESP", "AUTH3",
  "SHUTDOWN", "CO_CANCEL", "ORPHANED"]

proc prettyRpc*(d: openArray[byte]): seq[PrettyLine] =
  if d.len < 16:
    result.add PrettyLine(offset: 0, name: "(truncated)",
                           value: hex(d))
    return
  let b = newBuffer(@d)
  let h = pdu.readHeader(b)
  result.add PrettyLine(offset: 0, name: "rpc_vers",
                         value: $h.rpcVersion)
  result.add PrettyLine(offset: 1, name: "rpc_vers_minor",
                         value: $h.rpcMinor)
  let ptName =
    if int(ord(h.pType)) < PduTypeNames.len:
      PduTypeNames[ord(h.pType)]
    else: "?"
  result.add PrettyLine(offset: 2, name: "PTYPE", value: ptName,
                         note: "0x" & toHex(ord(h.pType), 2))
  var flagBits: string
  if pfcFirstFrag in h.flags: flagBits.add "FIRST "
  if pfcLastFrag  in h.flags: flagBits.add "LAST "
  if pfcPendingCancel in h.flags: flagBits.add "CANCEL "
  if pfcConcurrentMpx in h.flags: flagBits.add "MPX "
  if pfcObjectUuid in h.flags: flagBits.add "OBJUUID "
  result.add PrettyLine(offset: 3, name: "pfc_flags",
                         value: "0x" & toHex(int(flagsToByte(h.flags)), 2),
                         note: flagBits.strip)
  result.add PrettyLine(offset: 4, name: "packed_drep",
                         value: hex(h.dataRep),
                         note: if (h.dataRep[0] and 0xF0'u8) == 0x10'u8:
                                "little-endian"
                              else: "big-endian")
  result.add PrettyLine(offset: 8, name: "frag_length",
                         value: $h.fragLen)
  result.add PrettyLine(offset: 10, name: "auth_length",
                         value: $h.authLen)
  result.add PrettyLine(offset: 12, name: "call_id",
                         value: $h.callId)
  if d.len > 16:
    result.add PrettyLine(offset: 16, name: "Body",
                           value: hex(d[16 ..< d.len], maxLen = 48))
  if h.authLen > 0 and d.len >= int(h.fragLen):
    let authStart = int(h.fragLen) - int(h.authLen)
    result.add PrettyLine(offset: authStart - 8, name: "sec_trailer",
                           value: hex(d[authStart - 8 ..< authStart]),
                           note: "auth_type/level/pad/reserved/ctx_id")
    result.add PrettyLine(offset: authStart, name: "auth_value",
                           value: hex(d[authStart ..< int(h.fragLen)],
                                       maxLen = 64))

# --- NTLMSSP ------------------------------------------------------

proc prettyNtlm*(d: openArray[byte]): seq[PrettyLine] =
  result.add PrettyLine(offset: 0, name: "Magic", value: "NTLMSSP\\0")
  if d.len < 12: return
  let msgType = uint32(d[8]) or (uint32(d[9]) shl 8) or
                (uint32(d[10]) shl 16) or (uint32(d[11]) shl 24)
  let msgName = case msgType
    of 1'u32: "NEGOTIATE"
    of 2'u32: "CHALLENGE"
    of 3'u32: "AUTHENTICATE"
    else: "unknown"
  result.add PrettyLine(offset: 8, name: "MessageType",
                         value: $msgType, note: msgName)
  case msgType
  of 1'u32:
    try:
      let n = parseNegotiate(d)
      result.add PrettyLine(offset: 12, name: "NegotiateFlags",
                             value: "0x" & toHex(int64(toU32(n.flags)), 8))
      result.add PrettyLine(offset: 16, name: "Domain",
                             value: n.domain)
      result.add PrettyLine(offset: 24, name: "Workstation",
                             value: n.workstation)
    except CatchableError:
      result.add PrettyLine(offset: 12, name: "(parse error)",
                             value: hex(d[12 ..< d.len], maxLen = 32))
  of 2'u32:
    try:
      let c = parseChallenge(d)
      result.add PrettyLine(offset: 12, name: "TargetName",
                             value: c.targetName)
      result.add PrettyLine(offset: 20, name: "NegotiateFlags",
                             value: "0x" & toHex(int64(toU32(c.flags)), 8))
      result.add PrettyLine(offset: 24, name: "ServerChallenge",
                             value: hex(c.serverChallenge))
    except CatchableError:
      result.add PrettyLine(offset: 12, name: "(parse error)",
                             value: hex(d[12 ..< d.len], maxLen = 32))
  of 3'u32:
    result.add PrettyLine(offset: 12, name: "Body",
                           value: hex(d[12 ..< d.len], maxLen = 64))
  else: discard

# --- top-level entry --------------------------------------------

proc pretty*(d: openArray[byte]; force: Protocol = pAuto): string =
  let p = if force == pAuto: sniffProtocol(d) else: force
  case p
  of pSmb2:
    result = "Protocol: SMB2/SMB3\n"
    result.add formatLines(prettySmb2(d))
  of pRpc:
    result = "Protocol: DCE-RPC\n"
    result.add formatLines(prettyRpc(d))
  of pNtlm:
    result = "Protocol: NTLMSSP\n"
    result.add formatLines(prettyNtlm(d))
  of pKrb:
    result = "Protocol: Kerberos (KRB5)\n"
    let appTag = d[0]
    let tagName = case appTag
      of 0x6A'u8: "AS-REQ [APPLICATION 10]"
      of 0x6B'u8: "AS-REP [APPLICATION 11]"
      of 0x6C'u8: "TGS-REQ [APPLICATION 12]"
      of 0x6D'u8: "TGS-REP [APPLICATION 13]"
      of 0x6E'u8: "AP-REQ [APPLICATION 14]"
      of 0x6F'u8: "AP-REP [APPLICATION 15]"
      of 0x7E'u8: "KRB-ERROR [APPLICATION 30]"
      else: "unknown"
    result.add fmt"  Outer tag: 0x{appTag.hexByte} ({tagName})" & "\n"
    result.add fmt"  Length:    {d.len} bytes" & "\n"
    result.add fmt"  First 64:  {hex(d, 64)}" & "\n"
  of pLdap:
    result = "Protocol: LDAP\n"
    result.add fmt"  Outer SEQUENCE, {d.len} bytes" & "\n"
    result.add fmt"  First 64:  {hex(d, 64)}" & "\n"
  of pUnknown, pAuto:
    result = "Protocol: unknown\n"
    result.add fmt"  {d.len} bytes" & "\n"
    result.add fmt"  Hex:    {hex(d, 96)}" & "\n"
    result.add fmt"  ASCII:  {ascii(d, 64)}" & "\n"

# --- public helper for the CLI tool ----------------------------

proc prettyFromHex*(hexStr: string; force: Protocol = pAuto): string =
  ## Parse a whitespace-tolerant hex string and pretty-print it.
  var clean = newStringOfCap(hexStr.len)
  for c in hexStr:
    if c in "0123456789abcdefABCDEF": clean.add c
  if clean.len mod 2 != 0:
    return "input has odd number of hex digits"
  var bytes = newSeq[byte](clean.len div 2)
  for i in 0 ..< bytes.len:
    bytes[i] = byte(parseHexInt(clean[2*i .. 2*i+1]))
  result = pretty(bytes, force)
