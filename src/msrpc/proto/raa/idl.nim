## proto/raa/idl.nim — NDR marshallers for MS-RAA types + opnum stubs.
##
## Each opnum stub builds the IN-direction NDR buffer for the call, hands
## it to the RPC client, and decodes the OUT-direction NDR reply. The
## stubs are deliberately verbose to make the wire layout legible
## alongside the MS-RAA §3.1.4 opnum specs.

import ../../common/[buffers, endian, guid, sid, status]
import ../../ndr/[context, primitives]
import ../../rpc/client
import types

# --- AUTHZR_CONTEXT_HANDLE ---------------------------------------------

proc marshal*(c: NdrContext; v: var AuthzrContextHandle) =
  ## MS-DTYP RPC_CONTEXT_HANDLE: u32 attributes, then uuid (mixed-endian).
  c.align(4)
  case c.dir
  of ndEncode:
    c.buf.writeU32LE(v.handleAttr)
    c.buf.writeWire(v.handleUuid)
  of ndDecode:
    v.handleAttr = c.buf.readU32LE()
    v.handleUuid = guid.readWire(c.buf)

# --- Object type list entry --------------------------------------------

proc marshal*(c: NdrContext; v: var ObjectTypeListEntry) =
  c.align(4)
  case c.dir
  of ndEncode:
    c.buf.writeU16LE(v.level)
    c.buf.writeU16LE(v.sbz)
    c.buf.writeU32LE(v.accessMask)
    c.buf.writeWire(v.objectType)
  of ndDecode:
    v.level = c.buf.readU16LE()
    v.sbz = c.buf.readU16LE()
    v.accessMask = c.buf.readU32LE()
    v.objectType = guid.readWire(c.buf)

# --- Opnum stubs (low-level) ------------------------------------------

# Opnum 0 — AuthzrFreeContext(in out [context_handle] h)
proc authzrFreeContext*(client: RpcClient;
                        h: var AuthzrContextHandle): NtStatus =
  let c = newNdrEncode(nsNdr)
  marshal(c, h)
  let reply = client.call(opnum = 0, stub = c.finish())

  let dc = newNdrDecode(reply, nsNdr)
  marshal(dc, h)
  # Trailing u32 status (Win32 error)
  var status: uint32
  marshal(dc, status)
  result = NtStatus(status)

# Opnum 1 — AuthzrInitializeContextFromSid(
#   in handle_t hBinding,
#   in DWORD Flags,
#   in PRPC_SID UserSid,
#   in PLARGE_INTEGER ExpirationTime,
#   in LUID Identifier,
#   out AUTHZR_HANDLE *ContextHandle)
proc authzrInitializeContextFromSid*(client: RpcClient;
                                      flags: uint32;
                                      userSid: Sid;
                                      expirationTime: int64;
                                      identifierLow: uint32;
                                      identifierHigh: uint32;
                                      handle: var AuthzrContextHandle
                                     ): NtStatus =
  let c = newNdrEncode(nsNdr)
  # Flags
  var f = flags
  marshal(c, f)
  # User SID: ref pointer to RPC_SID
  c.buf.writeU32LE(0x00020000'u32)   # non-null ref id (top-level ref ptr)
  c.buf.writeU32LE(uint32(userSid.subAuthCount))   # conformance count
  c.buf.writeWire(userSid)
  c.buf.alignTo(4)
  # ExpirationTime: unique pointer to LARGE_INTEGER
  if expirationTime != 0:
    c.buf.writeU32LE(0x00020004'u32)
    c.buf.alignTo(8)
    c.buf.writeU64LE(uint64(expirationTime))
  else:
    c.buf.writeU32LE(0)
  # Identifier (LUID): two u32
  c.buf.writeU32LE(identifierLow)
  c.buf.writeU32LE(identifierHigh)

  let reply = client.call(opnum = 1, stub = c.finish())
  let dc = newNdrDecode(reply, nsNdr)
  marshal(dc, handle)
  var status: uint32
  marshal(dc, status)
  result = NtStatus(status)

# Opnum 3 — AuthzrAccessCheck.
#
# IDL (MS-RAA §3.1.4.1):
#
#   DWORD AuthzrAccessCheck(
#     [in] handle_t hBinding,
#     [in] AUTHZR_HANDLE hAuthzrHandle,
#     [in] DWORD Flags,
#     [in] PAUTHZR_ACCESS_REQUEST pRequest,
#     [in] DWORD SecurityDescriptorCount,
#     [in, size_is(SecurityDescriptorCount)]
#          AUTHZR_SECURITY_DESCRIPTOR *pSecurityDescriptors,
#     [in, out] PAUTHZR_ACCESS_REPLY pReply);
#
# Where:
#   AUTHZR_SECURITY_DESCRIPTOR { u32 len; [size_is(len)] BYTE *bytes; }
#   AUTHZR_ACCESS_REQUEST { DesiredAccess; unique PRPC_SID;
#                          ObjectTypeListLength; unique ObjectTypeList[];
#                          OptionalArgumentsLength; unique bytes[]; }
#   AUTHZR_ACCESS_REPLY  { ResultListLength;
#                          [size_is(.)] DWORD *GrantedAccessMask;
#                          [size_is(.)] DWORD *SaclEvaluationResults;
#                          [size_is(.)] DWORD *Error; }

proc buildAccessCheckStub*(handle: AuthzrContextHandle;
                            flags: uint32;
                            desiredAccess: uint32;
                            principalSelfSid: ref Sid;
                            objectTypeList: openArray[ObjectTypeListEntry];
                            optionalArguments: openArray[byte];
                            securityDescriptor: openArray[byte];
                            resultListLength: uint32 = 1): seq[byte] =
  ## NDR encoder for AuthzrAccessCheck IN params.
  let c = newNdrEncode(nsNdr)

  # hAuthzrHandle (top-level context handle)
  var h = handle
  marshal(c, h)

  # Flags
  c.align(4)
  c.buf.writeU32LE(flags)

  # pRequest : ref pointer (top-level) ⇒ inline struct, no refid.
  c.align(4)
  # AUTHZR_ACCESS_REQUEST inline:
  c.buf.writeU32LE(desiredAccess)

  # PrincipalSelfSid (unique pointer to RPC_SID)
  let sidRefId: uint32 = if principalSelfSid != nil: 0x00020000'u32 else: 0
  c.buf.writeU32LE(sidRefId)

  # ObjectTypeListLength + ObjectTypeList (unique pointer to OTL[])
  let otlLen = uint32(objectTypeList.len)
  c.buf.writeU32LE(otlLen)
  let otlRefId: uint32 = if otlLen > 0: 0x00020004'u32 else: 0
  c.buf.writeU32LE(otlRefId)

  # OptionalArgumentsLength + OptionalArguments (unique pointer)
  let optLen = uint32(optionalArguments.len)
  c.buf.writeU32LE(optLen)
  let optRefId: uint32 = if optLen > 0: 0x00020008'u32 else: 0
  c.buf.writeU32LE(optRefId)

  # Deferred body for PrincipalSelfSid (if any).
  if principalSelfSid != nil:
    let sid = principalSelfSid[]
    c.align(4)
    c.buf.writeU32LE(uint32(sid.subAuthority.len))   # max_count conformance
    c.buf.writeWire(sid)
    c.align(4)

  # Deferred body for ObjectTypeList (if any).
  if otlLen > 0:
    c.align(4)
    c.buf.writeU32LE(otlLen)               # max_count conformance
    for e in objectTypeList:
      var entry = e
      marshal(c, entry)

  # Deferred body for OptionalArguments (if any).
  if optLen > 0:
    c.align(4)
    c.buf.writeU32LE(optLen)
    c.buf.writeBytes(optionalArguments)
    c.align(4)

  # SecurityDescriptorCount : u32 (always 1 here; the single SD is fed
  # via pSecurityDescriptors below).
  c.align(4)
  c.buf.writeU32LE(1)

  # pSecurityDescriptors : ref pointer (top-level) to
  # conformant array of AUTHZR_SECURITY_DESCRIPTOR{u32 len; bytes *p;}
  c.buf.writeU32LE(1)                      # conformance count = 1
  # AUTHZR_SECURITY_DESCRIPTOR[0]:
  c.buf.writeU32LE(uint32(securityDescriptor.len))
  c.buf.writeU32LE(0x0002000C'u32)         # SD bytes referent id
  # Deferred: SD bytes as conformant array of bytes.
  c.buf.writeU32LE(uint32(securityDescriptor.len))
  c.buf.writeBytes(securityDescriptor)
  c.align(4)

  # pReply : in/out ref pointer — supply ResultListLength + null pointers.
  c.buf.writeU32LE(resultListLength)
  c.buf.writeU32LE(0)                      # GrantedAccessMask ptr (null on IN)
  c.buf.writeU32LE(0)                      # SaclEvaluationResults ptr
  c.buf.writeU32LE(0)                      # Error ptr

  result = c.finish()

proc parseAccessCheckReply*(reply: openArray[byte];
                             expectedCount: uint32 = 1): AuthzrAccessReply =
  ## Parse the OUT-direction NDR. Returns the granted-access masks
  ## and per-object error codes.
  let dc = newNdrDecode(reply, nsNdr)
  # pReply : ResultListLength + three conformant-array unique pointers.
  result.resultListLength = dc.buf.readU32LE()

  proc readMaskArray(): seq[uint32] =
    let refId = dc.buf.readU32LE()
    if refId == 0: return @[]
    let maxCount = dc.buf.readU32LE()
    result = newSeq[uint32](int(maxCount))
    for i in 0 ..< int(maxCount):
      result[i] = dc.buf.readU32LE()

  result.grantedAccessMask = readMaskArray()
  result.saclEvaluationResults = readMaskArray()
  result.error = readMaskArray()

proc authzrAccessCheck*(client: RpcClient;
                        handle: AuthzrContextHandle;
                        flags: uint32;
                        request: AuthzrAccessRequest;
                        securityDescriptor: openArray[byte];
                        reply: var AuthzrAccessReply): NtStatus =
  let stub = buildAccessCheckStub(
    handle, flags,
    desiredAccess = request.desiredAccess,
    principalSelfSid = request.principalSelfSid,
    objectTypeList = request.objectTypeList,
    optionalArguments = request.optionalArgumentsBytes,
    securityDescriptor = securityDescriptor)

  let raw = client.call(opnum = 3, stub = stub)
  reply = parseAccessCheckReply(raw)
  # Trailing u32 status.
  if raw.len >= 4:
    let tail = raw.len - 4
    result = NtStatus(
      uint32(raw[tail]) or
      (uint32(raw[tail+1]) shl 8) or
      (uint32(raw[tail+2]) shl 16) or
      (uint32(raw[tail+3]) shl 24))
  else:
    result = STATUS_INVALID_PARAMETER

# Opnum 4 — AuthzGetInformationFromContext
proc authzrGetInformationFromContext*(client: RpcClient;
                                       handle: AuthzrContextHandle;
                                       infoClass: AuthzContextInformationClass;
                                       outBuf: var seq[byte]): NtStatus =
  let c = newNdrEncode(nsNdr)
  var h = handle
  marshal(c, h)
  var ic = uint32(ord(infoClass))
  marshal(c, ic)

  let reply = client.call(opnum = 4, stub = c.finish())
  outBuf = reply
  # Replies for this opnum vary by InfoClass; the caller is responsible
  # for further decoding. Status is at the tail.
  if reply.len >= 4:
    let tail = reply.len - 4
    result = NtStatus(
      uint32(reply[tail]) or
      (uint32(reply[tail+1]) shl 8) or
      (uint32(reply[tail+2]) shl 16) or
      (uint32(reply[tail+3]) shl 24))
  else:
    result = STATUS_INVALID_PARAMETER
