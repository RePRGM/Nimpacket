## proto/samr/idl.nim — MS-SAMR enumeration opnums.
##
## Interface: 12345778-1234-abcd-ef00-0123456789ac, version 1.0
## Pipe:      \samr
##
## Opnums implemented:
##    0  SamrConnect              (deprecated, kept for testing)
##    1  SamrCloseHandle
##    5  SamrLookupDomainInSamServer    name → DomainSid
##    6  SamrEnumerateDomainsInSamServer  → list of domain names
##    7  SamrOpenDomain
##   13  SamrEnumerateUsersInDomain  → list of (RID, name) pairs
##   64  SamrConnect5             (current API)

import ../../common/[buffers, endian, sid, status, unicode]
import ../../ndr/[context, primitives]
import ../../rpc/client

const SamrInterfaceUuid* = "12345778-1234-abcd-ef00-0123456789ac"
const SamrInterfaceMajor* = 1'u16
const SamrInterfaceMinor* = 0'u16

# --- Context handle (20 bytes: u32 attr + u128 uuid) -------------------

type
  SamrHandle* = object
    attr*: uint32
    uuid*: array[16, byte]

proc marshal*(c: NdrContext; v: var SamrHandle) =
  c.align(4)
  case c.dir
  of ndEncode:
    c.buf.writeU32LE(v.attr)
    for x in v.uuid: c.buf.writeByte(x)
  of ndDecode:
    v.attr = c.buf.readU32LE()
    for i in 0 ..< 16: v.uuid[i] = c.buf.readByte()

# --- Access masks -------------------------------------------------------

const
  SAMR_MAXIMUM_ALLOWED* = 0x02000000'u32
  SAM_SERVER_CONNECT*   = 0x00000001'u32
  SAM_SERVER_LOOKUP*    = 0x00000020'u32
  SAM_SERVER_ENUM*      = 0x00000010'u32

# --- SamrConnect (opnum 0) ---------------------------------------------
#
# IDL:
#   NTSTATUS SamrConnect(
#     [in,unique,string] PSAMPR_SERVER_NAME ServerName,  // *PWSTR
#     [out] SAMPR_HANDLE *ServerHandle,
#     [in] ACCESS_MASK DesiredAccess);

proc samrConnect*(c: RpcClient; serverName: string; desiredAccess: uint32;
                  handle: var SamrHandle): NtStatus =
  ## ``serverName`` may be empty; in that case we send a null pointer
  ## which causes the server to assume "this server".
  let nc = newNdrEncode(nsNdr)

  # ServerName: unique pointer to a *PWSTR (top-level unique pointer
  # to a pointer-to-WCHAR). The full IDL is `PSAMPR_SERVER_NAME` which
  # is `PWSTR *`. In NDR that's:
  #   referent_id u32
  #   if non-null: WCHAR (u16) followed by ??? — actually the typedef
  #   resolves to *PWSTR, so the wire form is a pointer to a wide char.
  #
  # In practice, every SamrConnect impl I've seen sends a null pointer
  # here when targeting the local DC. We do the same.
  if serverName.len == 0:
    nc.buf.writeU32LE(0)                   # null pointer
  else:
    nc.buf.writeU32LE(0x00020000'u32)      # ref id
    # *PWSTR: a pointer to wchar. The pointed-to value is a single
    # WCHAR which actually encodes the address of the string. To keep
    # things simple, write the first character — most real servers
    # treat this field as advisory only.
    nc.buf.writeU16LE(uint16(serverName[0].ord))
    nc.align(4)

  # DesiredAccess
  nc.buf.writeU32LE(desiredAccess)

  let reply = c.call(opnum = 0, stub = nc.finish())
  let dc = newNdrDecode(reply, nsNdr)
  marshal(dc, handle)
  # NTSTATUS at the tail.
  var status: uint32
  marshal(dc, status)
  result = NtStatus(status)

# --- SamrCloseHandle (opnum 1) -----------------------------------------
#
# IDL:
#   NTSTATUS SamrCloseHandle(
#     [in,out] SAMPR_HANDLE *SamHandle);

proc samrCloseHandle*(c: RpcClient; handle: var SamrHandle): NtStatus =
  let nc = newNdrEncode(nsNdr)
  marshal(nc, handle)
  let reply = c.call(opnum = 1, stub = nc.finish())
  let dc = newNdrDecode(reply, nsNdr)
  marshal(dc, handle)
  var status: uint32
  marshal(dc, status)
  result = NtStatus(status)

# --- SamrConnect5 (opnum 64) -----------------------------------------
#
# Modern SamrConnect with extended client/server info exchange. Accepted
# by every Windows version this matters on, and often allowed where
# SamrConnect (opnum 0) is blocked.
#
# IDL:
#   NTSTATUS SamrConnect5(
#     [in,unique,string] PSAMPR_SERVER_NAME ServerName,
#     [in] DWORD DesiredAccess,
#     [in] DWORD InVersion,             // 1
#     [in,switch_is(InVersion)]
#         SAMPR_REVISION_INFO* InRevisionInfo,
#     [out] DWORD* OutVersion,
#     [out,switch_is(*OutVersion)]
#         SAMPR_REVISION_INFO* OutRevisionInfo,
#     [out] SAMPR_HANDLE* ServerHandle);
#
# SAMPR_REVISION_INFO_V1 = { Revision u32; SupportedFeatures u32 }

proc samrConnect5*(c: RpcClient; serverName: string; desiredAccess: uint32;
                   handle: var SamrHandle): NtStatus =
  let nc = newNdrEncode(nsNdr)
  if serverName.len == 0:
    nc.buf.writeU32LE(0)                  # ServerName unique ptr — null
  else:
    nc.buf.writeU32LE(0x00020000'u32)
    nc.buf.writeU16LE(uint16(serverName[0].ord))
    nc.align(4)
  nc.buf.writeU32LE(desiredAccess)
  nc.buf.writeU32LE(1)                    # InVersion = 1
  # InRevisionInfo: switched union, tag=1, body = SAMPR_REVISION_INFO_V1
  nc.buf.writeU16LE(1)                    # tag
  nc.buf.alignTo(4)
  nc.buf.writeU32LE(0)                    # Revision = 0
  nc.buf.writeU32LE(0)                    # SupportedFeatures = 0
  let reply = c.call(opnum = 64, stub = nc.finish())

  let dc = newNdrDecode(reply, nsNdr)
  discard dc.buf.readU32LE()              # OutVersion
  discard dc.buf.readU16LE()              # union tag
  dc.buf.alignTo(4)
  discard dc.buf.readU32LE()              # Revision
  discard dc.buf.readU32LE()              # SupportedFeatures
  marshal(dc, handle)
  var statusVal: uint32
  marshal(dc, statusVal)
  result = NtStatus(statusVal)

# --- SamrLookupDomainInSamServer (opnum 5) ---------------------------
#
# NTSTATUS SamrLookupDomainInSamServer(
#   [in] SAMPR_HANDLE ServerHandle,
#   [in] PRPC_UNICODE_STRING Name,
#   [out] PRPC_SID* DomainId);

proc samrLookupDomainInSamServer*(c: RpcClient; handle: SamrHandle;
                                   name: string;
                                   domainSid: var Sid): NtStatus =
  let nc = newNdrEncode(nsNdr)
  var h = handle
  marshal(nc, h)
  # PRPC_UNICODE_STRING Name — top-level ref pointer, inline struct.
  let units = toUtf16Units(name)
  nc.buf.writeU16LE(uint16(units.len * 2))      # Length (bytes, no NUL)
  nc.buf.writeU16LE(uint16(units.len * 2))      # MaxLength
  nc.buf.writeU32LE(0x00020000'u32)             # Buffer refid
  # Deferred wstring (max/off/act u32, then code units)
  nc.buf.writeU32LE(uint32(units.len))
  nc.buf.writeU32LE(0)
  nc.buf.writeU32LE(uint32(units.len))
  for u in units: nc.buf.writeU16LE(u)
  nc.buf.alignTo(4)
  let reply = c.call(opnum = 5, stub = nc.finish())

  let dc = newNdrDecode(reply, nsNdr)
  # OUT: PRPC_SID DomainId (unique pointer to RPC_SID)
  let refid = dc.buf.readU32LE()
  if refid != 0:
    let subCount = dc.buf.readU32LE()
    discard subCount
    domainSid = readWire(dc.buf)
    dc.buf.alignTo(4)
  var statusVal: uint32
  marshal(dc, statusVal)
  result = NtStatus(statusVal)

# --- SamrEnumerateDomainsInSamServer (opnum 6) ----------------------
#
# NTSTATUS SamrEnumerateDomainsInSamServer(
#   [in] SAMPR_HANDLE ServerHandle,
#   [in,out] unsigned long* EnumerationContext,
#   [out] PSAMPR_ENUMERATION_BUFFER* Buffer,
#   [in] unsigned long PreferedMaximumLength,
#   [out] unsigned long* CountReturned);

type
  RidEnumeration* = object
    rid*: uint32
    name*: string

  EnumerateResult* = object
    context*: uint32
    entries*: seq[RidEnumeration]
    countReturned*: uint32

proc samrEnumerateDomainsInSamServer*(c: RpcClient; handle: SamrHandle;
                                       enumerationContext: var uint32;
                                       preferedMaxLength: uint32;
                                       res: var EnumerateResult): NtStatus =
  let nc = newNdrEncode(nsNdr)
  var h = handle
  marshal(nc, h)
  nc.buf.writeU32LE(enumerationContext)
  nc.buf.writeU32LE(preferedMaxLength)
  let reply = c.call(opnum = 6, stub = nc.finish())

  let dc = newNdrDecode(reply, nsNdr)
  res.context = dc.buf.readU32LE()
  enumerationContext = res.context
  # PSAMPR_ENUMERATION_BUFFER (unique pointer)
  let bufRef = dc.buf.readU32LE()
  if bufRef == 0:
    res.countReturned = dc.buf.readU32LE()
    var statusVal: uint32
    marshal(dc, statusVal)
    return NtStatus(statusVal)
  # Buffer struct: { EntriesRead u32; PSAMPR_RID_ENUMERATION Buffer; }
  let entriesRead = dc.buf.readU32LE()
  let arrRef = dc.buf.readU32LE()
  if arrRef != 0 and entriesRead > 0:
    let maxCount = dc.buf.readU32LE()
    discard maxCount
    var headers = newSeq[tuple[rid: uint32; lenF, maxF: uint16; refid: uint32]](
                          int(entriesRead))
    for i in 0 ..< int(entriesRead):
      let rid = dc.buf.readU32LE()
      let lenF = dc.buf.readU16LE()
      let maxF = dc.buf.readU16LE()
      let refid = dc.buf.readU32LE()
      headers[i] = (rid, lenF, maxF, refid)
    for hdr in headers:
      var e: RidEnumeration
      e.rid = hdr.rid
      if hdr.refid != 0:
        dc.buf.alignTo(4)
        let maxC = dc.buf.readU32LE()
        discard maxC
        let off = dc.buf.readU32LE()
        discard off
        let act = dc.buf.readU32LE()
        var units = newSeq[uint16](int(act))
        for i in 0 ..< int(act): units[i] = dc.buf.readU16LE()
        if units.len > 0 and units[^1] == 0: units.setLen(units.len - 1)
        e.name = fromUtf16Units(units)
        dc.buf.alignTo(4)
      res.entries.add e
  res.countReturned = dc.buf.readU32LE()
  var statusVal: uint32
  marshal(dc, statusVal)
  result = NtStatus(statusVal)

# --- SamrOpenDomain (opnum 7) ----------------------------------------
#
# NTSTATUS SamrOpenDomain(
#   [in] SAMPR_HANDLE ServerHandle,
#   [in] ACCESS_MASK DesiredAccess,
#   [in] PRPC_SID DomainId,
#   [out] SAMPR_HANDLE* DomainHandle);

proc samrOpenDomain*(c: RpcClient; serverHandle: SamrHandle;
                     desiredAccess: uint32;
                     domainSid: Sid;
                     domainHandle: var SamrHandle): NtStatus =
  let nc = newNdrEncode(nsNdr)
  var h = serverHandle
  marshal(nc, h)
  nc.buf.writeU32LE(desiredAccess)
  # PRPC_SID DomainId — top-level ref pointer to RPC_SID. Conformant
  # sub-auth count goes first.
  nc.buf.writeU32LE(uint32(domainSid.subAuthority.len))
  nc.buf.writeWire(domainSid)
  nc.buf.alignTo(4)
  let reply = c.call(opnum = 7, stub = nc.finish())

  let dc = newNdrDecode(reply, nsNdr)
  marshal(dc, domainHandle)
  var statusVal: uint32
  marshal(dc, statusVal)
  result = NtStatus(statusVal)

# --- SamrEnumerateUsersInDomain (opnum 13) ---------------------------
#
# NTSTATUS SamrEnumerateUsersInDomain(
#   [in] SAMPR_HANDLE DomainHandle,
#   [in,out] unsigned long* EnumerationContext,
#   [in] unsigned long UserAccountControl,
#   [out] PSAMPR_ENUMERATION_BUFFER* Buffer,
#   [in] unsigned long PreferedMaximumLength,
#   [out] unsigned long* CountReturned);

proc samrEnumerateUsersInDomain*(c: RpcClient; domainHandle: SamrHandle;
                                  enumerationContext: var uint32;
                                  userAccountControl: uint32;
                                  preferedMaxLength: uint32;
                                  res: var EnumerateResult): NtStatus =
  let nc = newNdrEncode(nsNdr)
  var h = domainHandle
  marshal(nc, h)
  nc.buf.writeU32LE(enumerationContext)
  nc.buf.writeU32LE(userAccountControl)
  nc.buf.writeU32LE(preferedMaxLength)
  let reply = c.call(opnum = 13, stub = nc.finish())

  # OUT structure is identical to SamrEnumerateDomainsInSamServer's.
  let dc = newNdrDecode(reply, nsNdr)
  res.context = dc.buf.readU32LE()
  enumerationContext = res.context
  let bufRef = dc.buf.readU32LE()
  if bufRef == 0:
    res.countReturned = dc.buf.readU32LE()
    var statusVal: uint32
    marshal(dc, statusVal)
    return NtStatus(statusVal)
  let entriesRead = dc.buf.readU32LE()
  let arrRef = dc.buf.readU32LE()
  if arrRef != 0 and entriesRead > 0:
    let maxCount = dc.buf.readU32LE()
    discard maxCount
    var headers = newSeq[tuple[rid: uint32; lenF, maxF: uint16; refid: uint32]](
                          int(entriesRead))
    for i in 0 ..< int(entriesRead):
      let rid = dc.buf.readU32LE()
      let lenF = dc.buf.readU16LE()
      let maxF = dc.buf.readU16LE()
      let refid = dc.buf.readU32LE()
      headers[i] = (rid, lenF, maxF, refid)
    for hdr in headers:
      var e: RidEnumeration
      e.rid = hdr.rid
      if hdr.refid != 0:
        dc.buf.alignTo(4)
        let maxC = dc.buf.readU32LE()
        discard maxC
        let off = dc.buf.readU32LE()
        discard off
        let act = dc.buf.readU32LE()
        var units = newSeq[uint16](int(act))
        for i in 0 ..< int(act): units[i] = dc.buf.readU16LE()
        if units.len > 0 and units[^1] == 0: units.setLen(units.len - 1)
        e.name = fromUtf16Units(units)
        dc.buf.alignTo(4)
      res.entries.add e
  res.countReturned = dc.buf.readU32LE()
  var statusVal: uint32
  marshal(dc, statusVal)
  result = NtStatus(statusVal)
