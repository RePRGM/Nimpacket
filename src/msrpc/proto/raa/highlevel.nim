## proto/raa/highlevel.nim — user-facing facade.
##
## Hides the BIND / authenticate / discover-port / call dance behind
## a small set of types. The low-level opnum wrappers in idl.nim remain
## available for callers that need them.

import ../../common/[guid, sid, status]
import ../../rpc/[client, transport_tcp]
import types, idl

type
  RaaCredentials* = object
    domain*, username*, password*: string

  RaaAccessRequest* = object
    desiredAccess*: uint32
    objectTypeList*: seq[ObjectTypeListEntry]

  RaaCheckResult* = object
    granted*: bool
    grantedMask*: uint32
    error*: NtStatus

  RaaSession* = ref object
    client*: RpcClient
    contextHandle*: AuthzrContextHandle
    open*: bool

# --- session lifecycle -------------------------------------------------

proc openRaaSession*(host: string; port: int;
                     creds: RaaCredentials;
                     subjectSid: Sid): RaaSession =
  ## Connect to ``host:port``, BIND to the RAA interface (no auth in
  ## this initial drop — see the auth follow-up), and initialize a
  ## context handle for ``subjectSid``.
  let t = newTcpTransport(host, port)
  let raaUuid = parseUuid(RaaInterfaceUuid)
  let rpc = connect(t, raaUuid,
                    interfaceVersion = uint32(RaaInterfaceMajor))
  result = RaaSession(client: rpc, open: false)

  var h: AuthzrContextHandle
  let st = authzrInitializeContextFromSid(
    rpc, flags = 0, userSid = subjectSid,
    expirationTime = 0, identifierLow = 0, identifierHigh = 0,
    handle = h)
  st.raiseIfError("InitializeContextFromSid")
  result.contextHandle = h
  result.open = true

proc close*(s: RaaSession) =
  if not s.open: return
  var h = s.contextHandle
  discard authzrFreeContext(s.client, h)
  s.client.close()
  s.open = false

# --- one-shot access check --------------------------------------------

proc accessCheck*(s: RaaSession;
                  req: RaaAccessRequest;
                  securityDescriptor: openArray[byte]): RaaCheckResult =
  ## Note: the AuthzrAccessCheck NDR encoder is a stub in idl.nim; this
  ## helper documents the intended high-level shape but currently
  ## raises until the encoder is completed.
  let request = AuthzrAccessRequest(
    desiredAccess: req.desiredAccess,
    principalSelfSid: nil,
    objectTypeList: req.objectTypeList,
    optionalArgumentsBytes: @[])
  var reply: AuthzrAccessReply
  let st = authzrAccessCheck(s.client, s.contextHandle,
                             flags = 0, request, securityDescriptor, reply)
  if st.isError:
    result.granted = false
    result.error = st
    return
  if reply.grantedAccessMask.len > 0:
    result.granted = (reply.error.len == 0 or reply.error[0] == 0)
    result.grantedMask = reply.grantedAccessMask[0]
  result.error = st

# --- one-call convenience ---------------------------------------------

proc raaAccessCheck*(host: string; port: int;
                     creds: RaaCredentials;
                     subjectSid: Sid;
                     securityDescriptor: openArray[byte];
                     desiredAccess: uint32 = 0x02000000'u32): RaaCheckResult =
  ## Open → check → close in one call.
  let s = openRaaSession(host, port, creds, subjectSid)
  try:
    result = s.accessCheck(
      RaaAccessRequest(desiredAccess: desiredAccess), securityDescriptor)
  finally:
    s.close()
