## proto/srvs/idl.nim — MS-SRVS (Server Service Remote Protocol).
##
## Interface: 4b324fc8-1670-01d3-1278-5a47bf6ee188, version 3.0
## Pipe:      \srvsvc
##
## Opnums implemented:
##   15  NetrShareEnum             list network shares (info level 1)
##   16  NetrShareGetInfo          one share's details (deferred)
##
## ``net view \\HOST`` from a Windows command line and ``smbclient -L
## //host`` from Samba both call NetrShareEnum level 1 against this
## interface. With an authenticated session, most Windows hosts allow
## any user to enumerate.

import ../../common/[buffers, endian, status, unicode]
import ../../ndr/[context, primitives]
import ../../rpc/client

const SrvsInterfaceUuid* = "4b324fc8-1670-01d3-1278-5a47bf6ee188"
const SrvsInterfaceMajor* = 3'u16
const SrvsInterfaceMinor* = 0'u16

# --- well-known share types (lower 31 bits = kind, high bit = special)
const
  STYPE_DISKTREE*  = 0x00000000'u32
  STYPE_PRINTQ*    = 0x00000001'u32
  STYPE_DEVICE*    = 0x00000002'u32
  STYPE_IPC*       = 0x00000003'u32
  STYPE_SPECIAL*   = 0x80000000'u32   # hidden ($-suffixed shares)
  STYPE_TEMPORARY* = 0x40000000'u32

# --- public result type --------------------------------------------

type
  ShareInfo1* = object
    netname*: string
    shareType*: uint32
    remark*: string

# --- NetrShareEnum (opnum 15) --------------------------------------
#
# NET_API_STATUS NetrShareEnum(
#   [in,string,unique] SRVSVC_HANDLE ServerName,
#   [in,out] LPSHARE_ENUM_STRUCT InfoStruct,
#   [in] DWORD PreferedMaximumLength,
#   [out] DWORD *TotalEntries,
#   [in,out,unique] DWORD *ResumeHandle);
#
# Wire layout for InfoStruct at level 1:
#   IN:
#     Level (DWORD = 1)
#     [switch] tag (DWORD = 1)
#     Container ptr (unique = 0x00020000)
#       deferred: EntriesRead = 0
#                 Buffer ptr (unique = 0)   -- empty array
#   OUT:
#     Level (DWORD)
#     [switch] tag
#     Container ptr (unique)
#       EntriesRead
#       Buffer ptr (unique)
#         array of SHARE_INFO_1:
#           netname ptr (unique), type DWORD, remark ptr (unique)
#         deferred: each name and remark as conformant-varying wstring

proc netrShareEnum*(rpc: RpcClient; serverName: string;
                    preferedMax: uint32;
                    shares: var seq[ShareInfo1];
                    totalEntries: var uint32;
                    resumeHandle: var uint32): NtStatus =
  let c = newNdrEncode(nsNdr)

  # ServerName: unique pointer to wstring (use NULL).
  if serverName.len == 0:
    c.buf.writeU32LE(0)
  else:
    c.buf.writeU32LE(0x00020000)
    let units = toUtf16Units(serverName)
    let n = units.len + 1
    c.buf.writeU32LE(uint32(n))
    c.buf.writeU32LE(0)
    c.buf.writeU32LE(uint32(n))
    for u in units: c.buf.writeU16LE(u)
    c.buf.writeU16LE(0)
    c.buf.alignTo(4)

  # InfoStruct (top-level ref → no refid). Inline:
  #   Level=1, then union body for case 1 (container ptr).
  c.buf.writeU32LE(1)                     # Level
  c.buf.writeU32LE(1)                     # switch tag
  c.buf.writeU32LE(0x00020004)            # Container ptr (unique, non-null)
  # Deferred SHARE_INFO_1_CONTAINER:
  c.buf.writeU32LE(0)                     # EntriesRead = 0 on IN
  c.buf.writeU32LE(0)                     # Buffer ptr null on IN

  # PreferedMaximumLength
  c.buf.writeU32LE(preferedMax)

  # ResumeHandle (unique pointer to DWORD)
  if resumeHandle == 0:
    c.buf.writeU32LE(0)
  else:
    c.buf.writeU32LE(0x00020008)
    c.buf.writeU32LE(resumeHandle)

  let reply = rpc.call(opnum = 15, stub = c.finish())
  let dc = newNdrDecode(reply, nsNdr)

  let outLevel = dc.buf.readU32LE()
  let outTag = dc.buf.readU32LE()
  doAssert outLevel == 1 and outTag == 1, "unexpected SHARE_ENUM level"
  let containerRef = dc.buf.readU32LE()
  shares = @[]
  if containerRef != 0:
    let entriesRead = dc.buf.readU32LE()
    let bufRef = dc.buf.readU32LE()
    if bufRef != 0 and entriesRead > 0:
      let maxCount = dc.buf.readU32LE()
      discard maxCount
      # Inline part of SHARE_INFO_1 array: tuple (netname_ref, type, remark_ref).
      var rows = newSeq[tuple[nameRef, typ, remarkRef: uint32]](int(entriesRead))
      for i in 0 ..< int(entriesRead):
        rows[i].nameRef = dc.buf.readU32LE()
        rows[i].typ     = dc.buf.readU32LE()
        rows[i].remarkRef = dc.buf.readU32LE()
      # Deferred wstrings: name then remark for each entry, in order.
      proc readWstr(): string =
        dc.buf.alignTo(4)
        let maxC = dc.buf.readU32LE()
        discard maxC
        let off = dc.buf.readU32LE()
        discard off
        let act = dc.buf.readU32LE()
        var units = newSeq[uint16](int(act))
        for i in 0 ..< int(act): units[i] = dc.buf.readU16LE()
        if units.len > 0 and units[^1] == 0: units.setLen(units.len - 1)
        result = fromUtf16Units(units)
      for r in rows:
        var entry: ShareInfo1
        entry.shareType = r.typ
        if r.nameRef != 0:
          entry.netname = readWstr()
        if r.remarkRef != 0:
          entry.remark = readWstr()
        shares.add entry

  # TotalEntries
  dc.buf.alignTo(4)
  totalEntries = dc.buf.readU32LE()
  # ResumeHandle (unique ptr to DWORD)
  let resumeRef = dc.buf.readU32LE()
  resumeHandle = if resumeRef != 0: dc.buf.readU32LE() else: 0
  var st: uint32
  marshal(dc, st)
  result = NtStatus(st)

# --- helper: pretty-print share type -------------------------------

proc shareTypeName*(t: uint32): string =
  let base = t and 0x0FFFFFFF
  let baseName = case base
    of STYPE_DISKTREE: "DISK"
    of STYPE_PRINTQ:   "PRINTER"
    of STYPE_DEVICE:   "DEVICE"
    of STYPE_IPC:      "IPC"
    else: "TYPE(" & $base & ")"
  var suffix = ""
  if (t and STYPE_SPECIAL) != 0: suffix.add ",SPECIAL"
  if (t and STYPE_TEMPORARY) != 0: suffix.add ",TEMP"
  result = baseName & suffix
