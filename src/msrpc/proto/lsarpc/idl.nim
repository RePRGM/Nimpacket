## proto/lsarpc/idl.nim — MS-LSAT / MS-LSAD opnums for SID/name translation.
##
## Interface: 12345778-1234-abcd-ef00-0123456789ab, version 0.0
## Pipe:      \lsarpc  (also reachable as \netlogon on most hosts)
##
## Opnums implemented:
##   0  LsarClose
##   7  LsarQueryInformationPolicy
##   14 LsarLookupNames    (names → SIDs)
##   15 LsarLookupSids     (SIDs → names)
##   44 LsarOpenPolicy2

import ../../common/[buffers, endian, sid, status, unicode]
import ../../ndr/[context, primitives, strings]
import ../../rpc/client

const LsarInterfaceUuid* = "12345778-1234-abcd-ef00-0123456789ab"
const LsarInterfaceMajor* = 0'u16
const LsarInterfaceMinor* = 0'u16

# --- handle (20 bytes: u32 attr + 16-byte uuid) -----------------------

type
  LsarHandle* = object
    attr*: uint32
    uuid*: array[16, byte]

proc marshal*(c: NdrContext; v: var LsarHandle) =
  c.align(4)
  case c.dir
  of ndEncode:
    c.buf.writeU32LE(v.attr)
    for x in v.uuid: c.buf.writeByte(x)
  of ndDecode:
    v.attr = c.buf.readU32LE()
    for i in 0 ..< 16: v.uuid[i] = c.buf.readByte()

# --- common access masks (MS-LSAD §2.2.1.1.2) -------------------------

const
  POLICY_VIEW_LOCAL_INFORMATION*   = 0x00000001'u32
  POLICY_VIEW_AUDIT_INFORMATION*   = 0x00000002'u32
  POLICY_GET_PRIVATE_INFORMATION*  = 0x00000004'u32
  POLICY_TRUST_ADMIN*              = 0x00000008'u32
  POLICY_CREATE_ACCOUNT*           = 0x00000010'u32
  POLICY_LOOKUP_NAMES*             = 0x00000800'u32
  POLICY_MAXIMUM_ALLOWED*          = 0x02000000'u32

# --- LsarOpenPolicy2 (opnum 44) --------------------------------------
#
# NTSTATUS LsarOpenPolicy2(
#   [in,unique,string] WCHAR* SystemName,
#   [in] PLSAPR_OBJECT_ATTRIBUTES ObjectAttributes,
#   [in] ACCESS_MASK DesiredAccess,
#   [out] LSAPR_HANDLE* PolicyHandle);
#
# Wire format used by every common LSARPC client (impacket, samba,
# Windows SetUp). SystemName is sent as null; ObjectAttributes is
# 24 bytes of "all fields null/zero":

proc buildOpenPolicy2*(systemName: string; desiredAccess: uint32): seq[byte] =
  let c = newNdrEncode(nsNdr)
  # SystemName unique pointer to PWSTR — null
  c.buf.writeU32LE(0)
  # ObjectAttributes inline (top-level ref pointer, no refid on wire):
  c.buf.writeU32LE(24)              # Length
  c.buf.writeU32LE(0)               # RootDirectory unique ptr (null)
  c.buf.writeU32LE(0)               # ObjectName unique ptr (null)
  c.buf.writeU32LE(0)               # Attributes
  c.buf.writeU32LE(0)               # SecurityDescriptor unique ptr (null)
  c.buf.writeU32LE(0)               # SecurityQualityOfService unique ptr (null)
  # DesiredAccess
  c.buf.writeU32LE(desiredAccess)
  result = c.finish()

proc lsarOpenPolicy2*(rpc: RpcClient; systemName: string;
                      desiredAccess: uint32;
                      handle: var LsarHandle): NtStatus =
  let stub = buildOpenPolicy2(systemName, desiredAccess)
  let reply = rpc.call(opnum = 44, stub = stub)
  let dc = newNdrDecode(reply, nsNdr)
  marshal(dc, handle)
  var statusVal: uint32
  marshal(dc, statusVal)
  result = NtStatus(statusVal)

# --- LsarClose (opnum 0) ---------------------------------------------

proc lsarClose*(rpc: RpcClient; handle: var LsarHandle): NtStatus =
  let c = newNdrEncode(nsNdr)
  marshal(c, handle)
  let reply = rpc.call(opnum = 0, stub = c.finish())
  let dc = newNdrDecode(reply, nsNdr)
  marshal(dc, handle)
  var statusVal: uint32
  marshal(dc, statusVal)
  result = NtStatus(statusVal)

# --- LsarQueryInformationPolicy (opnum 7) ----------------------------
#
# NTSTATUS LsarQueryInformationPolicy(
#   [in] LSAPR_HANDLE PolicyHandle,
#   [in] POLICY_INFORMATION_CLASS InformationClass,
#   [out, switch_is(InformationClass)] PLSAPR_POLICY_INFORMATION* PolicyInformation);

type
  PolicyInfoClass* = enum
    PolicyAuditLogInformation              = 1
    PolicyAuditEventsInformation           = 2
    PolicyPrimaryDomainInformation         = 3
    PolicyPdAccountInformation             = 4
    PolicyAccountDomainInformation         = 5
    PolicyLsaServerRoleInformation         = 6
    PolicyReplicaSourceInformation         = 7
    PolicyDefaultQuotaInformation          = 8
    PolicyModificationInformation          = 9
    PolicyAuditFullSetInformation          = 10
    PolicyAuditFullQueryInformation        = 11
    PolicyDnsDomainInformation             = 12

  PolicyAccountDomainInfo* = object
    domainName*: string
    domainSid*: Sid
    hasSid*: bool

proc lsarQueryAccountDomain*(rpc: RpcClient; handle: LsarHandle;
                              info: var PolicyAccountDomainInfo): NtStatus =
  ## Convenience wrapper for the most commonly-requested info class
  ## (PolicyAccountDomainInformation = 5).
  let c = newNdrEncode(nsNdr)
  var h = handle
  marshal(c, h)
  var infoClass: uint16 = uint16(ord(PolicyAccountDomainInformation))
  marshal(c, infoClass)
  let reply = rpc.call(opnum = 7, stub = c.finish())

  let dc = newNdrDecode(reply, nsNdr)
  # OUT: pointer to LSAPR_POLICY_INFORMATION union
  let refId = dc.buf.readU32LE()
  if refId == 0:
    var statusVal: uint32
    marshal(dc, statusVal)
    return NtStatus(statusVal)
  # Union discriminator (matches infoClass)
  dc.buf.alignTo(4)
  let disc = dc.buf.readU16LE()
  doAssert disc == uint16(ord(PolicyAccountDomainInformation))
  # LSAPR_POLICY_ACCOUNT_DOMAIN_INFO:
  #   RPC_UNICODE_STRING DomainName;
  #   PRPC_SID DomainSid;
  var domainName: RpcUnicodeString
  marshal(dc, domainName)
  let sidRefId = dc.buf.readU32LE()
  info.hasSid = (sidRefId != 0)
  dc.drainDeferred()
  info.domainName = domainName.value
  if info.hasSid:
    # Deferred: SID with conformant sub-auth count
    dc.buf.alignTo(4)
    let subAuthMax = dc.buf.readU32LE()
    discard subAuthMax
    info.domainSid = readWire(dc.buf)

  dc.buf.alignTo(4)
  var statusVal: uint32
  marshal(dc, statusVal)
  result = NtStatus(statusVal)

# --- LsarLookupSids (opnum 15) ---------------------------------------
#
# NTSTATUS LsarLookupSids(
#   [in] LSAPR_HANDLE PolicyHandle,
#   [in] PLSAPR_SID_ENUM_BUFFER SidEnumBuffer,
#   [out] PLSAPR_REFERENCED_DOMAIN_LIST* ReferencedDomains,
#   [in,out] PLSAPR_TRANSLATED_NAMES TranslatedNames,
#   [in] LSAP_LOOKUP_LEVEL LookupLevel,
#   [in,out] unsigned long* MappedCount);

type
  TranslatedName* = object
    sidUse*: uint16     ## SidTypeUser=1, SidTypeGroup=2, SidTypeDomain=3, ...
    name*: string
    domainIndex*: int32

  LookupSidsResult* = object
    domains*: seq[string]      ## referenced domain names (in same order as domainIndex refers to)
    names*: seq[TranslatedName]
    mappedCount*: uint32

proc lsarLookupSids*(rpc: RpcClient; handle: LsarHandle;
                     sids: openArray[Sid];
                     out_res: var LookupSidsResult;
                     lookupLevel: uint16 = 1): NtStatus =
  ## Translate one or more SIDs to names. ``lookupLevel`` 1 ==
  ## LsapLookupWksta (look up against local SAM + builtin domains).
  let nc = newNdrEncode(nsNdr)

  # PolicyHandle (top-level ref, 20 bytes inline)
  var h = handle
  marshal(nc, h)

  # PLSAPR_SID_ENUM_BUFFER SidEnumBuffer is a top-level ref pointer
  # (no refid). Struct is:
  #   unsigned long Entries;
  #   [size_is(Entries)] PRPC_SID *SidInfo;
  let entries = uint32(sids.len)
  nc.buf.writeU32LE(entries)
  # SidInfo: ref pointer to conformant array of unique pointers to SIDs.
  nc.buf.writeU32LE(0x00020000'u32)        # SidInfo array refid
  nc.buf.writeU32LE(entries)               # max_count conformance
  # Per-SID unique pointer refids
  for i in 0 ..< sids.len:
    nc.buf.writeU32LE(0x00020004'u32 + uint32(i*4))
  # Deferred SID bodies — each preceded by conformant sub-auth-count.
  for s in sids:
    nc.buf.alignTo(4)
    nc.buf.writeU32LE(uint32(s.subAuthority.len))
    nc.buf.writeWire(s)
    nc.buf.alignTo(4)

  # TranslatedNames (in/out): { Entries u32 = 0; Names unique ptr = null }
  nc.buf.writeU32LE(0)                     # Entries
  nc.buf.writeU32LE(0)                     # Names ptr null

  # LookupLevel (u16, enum-aligned to 4)
  nc.buf.alignTo(2)
  nc.buf.writeU16LE(lookupLevel)
  nc.buf.alignTo(4)

  # MappedCount (u32, in/out)
  nc.buf.writeU32LE(0)

  let reply = rpc.call(opnum = 15, stub = nc.finish())
  let dc = newNdrDecode(reply, nsNdr)

  # OUT layout:
  #   PLSAPR_REFERENCED_DOMAIN_LIST* ReferencedDomains  (unique pointer)
  #   LSAPR_TRANSLATED_NAMES        TranslatedNames     (inline struct)
  #   unsigned long                 MappedCount
  #   NTSTATUS                      return

  # --- ReferencedDomains (unique pointer to LSAPR_REFERENCED_DOMAIN_LIST) ---
  let domRefId = dc.buf.readU32LE()
  out_res.domains = @[]
  var domainCount: uint32 = 0
  if domRefId != 0:
    # struct LSAPR_REFERENCED_DOMAIN_LIST:
    #   unsigned long Entries;
    #   [size_is(Entries)] PLSAPR_TRUST_INFORMATION Domains;
    #   unsigned long MaxEntries;
    domainCount = dc.buf.readU32LE()
    let domArrRef = dc.buf.readU32LE()
    discard dc.buf.readU32LE()             # MaxEntries
    if domArrRef != 0 and domainCount > 0:
      let domMax = dc.buf.readU32LE()
      discard domMax
      # Inline LSAPR_TRUST_INFORMATION array. Each:
      #   RPC_UNICODE_STRING Name;
      #   PRPC_SID Sid; (unique pointer)
      var nameHeaders = newSeq[tuple[len, max: uint16; refid: uint32]](
        int(domainCount))
      for i in 0 ..< int(domainCount):
        let lenF = dc.buf.readU16LE()
        let maxF = dc.buf.readU16LE()
        let refid = dc.buf.readU32LE()
        nameHeaders[i] = (lenF, maxF, refid)
        # plus SID pointer (unique)
        discard dc.buf.readU32LE()
      # Deferred: name string buffers, then SID bodies.
      for nh in nameHeaders:
        if nh.refid == 0:
          out_res.domains.add ""
          continue
        dc.buf.alignTo(4)
        let maxC = dc.buf.readU32LE()
        discard maxC
        let off = dc.buf.readU32LE()
        discard off
        let act = dc.buf.readU32LE()
        var units = newSeq[uint16](int(act))
        for i in 0 ..< int(act): units[i] = dc.buf.readU16LE()
        if units.len > 0 and units[^1] == 0: units.setLen(units.len - 1)
        out_res.domains.add fromUtf16Units(units)
        # Followed by the SID body (we discard it).
        dc.buf.alignTo(4)
        let subAuthMax = dc.buf.readU32LE()
        discard subAuthMax
        discard readWire(dc.buf)
        dc.buf.alignTo(4)

  # --- TranslatedNames (inline struct) ---
  #   unsigned long Entries;
  #   [size_is(Entries)] PLSAPR_TRANSLATED_NAME Names;
  let nameEntries = dc.buf.readU32LE()
  let nameArrRef = dc.buf.readU32LE()
  out_res.names = @[]
  if nameArrRef != 0 and nameEntries > 0:
    dc.buf.alignTo(4)
    let nMax = dc.buf.readU32LE()
    discard nMax
    var headers = newSeq[tuple[use: uint16; lenF, maxF: uint16; refid: uint32;
                                domIdx: int32]](int(nameEntries))
    for i in 0 ..< int(nameEntries):
      let u = dc.buf.readU16LE()
      # LSAPR_TRANSLATED_NAME struct alignment is 4 (because of the
      # 4-aligned RPC_UNICODE_STRING that follows). After the u16 Use
      # we need 2 bytes of padding before Name.Length.
      dc.buf.alignTo(4)
      let lenF = dc.buf.readU16LE()
      let maxF = dc.buf.readU16LE()
      let refid = dc.buf.readU32LE()
      let di = cast[int32](dc.buf.readU32LE())
      headers[i] = (u, lenF, maxF, refid, di)
    # Deferred name strings
    for h in headers:
      var tn: TranslatedName
      tn.sidUse = h.use
      tn.domainIndex = h.domIdx
      if h.refid == 0:
        tn.name = ""
      else:
        dc.buf.alignTo(4)
        let maxC = dc.buf.readU32LE()
        discard maxC
        let off = dc.buf.readU32LE()
        discard off
        let act = dc.buf.readU32LE()
        var units = newSeq[uint16](int(act))
        for i in 0 ..< int(act): units[i] = dc.buf.readU16LE()
        if units.len > 0 and units[^1] == 0: units.setLen(units.len - 1)
        tn.name = fromUtf16Units(units)
        dc.buf.alignTo(4)
      out_res.names.add tn

  # MappedCount
  dc.buf.alignTo(4)
  out_res.mappedCount = dc.buf.readU32LE()
  # NTSTATUS
  var statusVal: uint32
  marshal(dc, statusVal)
  result = NtStatus(statusVal)
