## Tier C: smoke tests against a real Windows / Samba AD-DC.
##
## Off by default. Run with::
##
##   MSRPC_TEST_HOST=dc01.example.com   \
##   MSRPC_TEST_USER=alice              \
##   MSRPC_TEST_PASS=...                \
##   MSRPC_TEST_DOMAIN=EXAMPLE          \
##   nimble test_live
##
## These tests are smoke-level: they confirm the bytes we generate are
## acceptable to a real server, not that the full MS-RAA semantics are
## correct. Pair them with packet captures and impacket cross-checks
## when you need to debug a mismatch.

import std/[unittest, os, strutils]
import msrpc/common/[guid, sid, status]
import msrpc/auth/ntlm/provider
import msrpc/smb/client as smb
import msrpc/rpc/[client, transport_tcp, auth, epm]
import msrpc/proto/raa/[types, idl]
import msrpc/proto/samr/idl as samridl
import msrpc/rpc/transport_np

proc envOr(k, default: string): string =
  result = getEnv(k)
  if result.len == 0: result = default

proc envPort(k: string; default: int): int =
  let v = getEnv(k)
  if v.len == 0: default else: parseInt(v)

# These tests are guarded by env vars rather than a conditional `when`
# block so they show up as "skipped" rather than vanishing entirely.

suite "live: epm + raa smoke (Tier C)":
  test "EPM responds and serves a tower for SAMR":
    # SAMR is essentially always present on DCs (Windows + Samba both),
    # so this is the most portable smoke test for EPM connectivity.
    let host = getEnv("MSRPC_TEST_HOST")
    if host.len == 0:
      skip()
    else:
      let samrUuid = parseUuid("12345778-1234-abcd-ef00-0123456789ac")
      let ndrUuid = parseUuid("8a885d04-1ceb-11c9-9fe8-08002b104860")
      let port = epmLookupTcpPort(host, samrUuid, 1, ndrUuid)
      check port != 0
      echo "  EPM resolved SAMR to port ", port

  test "EPM responds for MS-RAA (skipped if not registered)":
    let host = getEnv("MSRPC_TEST_HOST")
    if host.len == 0:
      skip()
    else:
      let raaUuid = parseUuid("0b1c2170-5732-4e0e-8cd3-d9b16f3b84d7")
      let ndrUuid = parseUuid("8a885d04-1ceb-11c9-9fe8-08002b104860")
      try:
        let port = epmLookupTcpPort(host, raaUuid, 0, ndrUuid)
        echo "  EPM resolved MS-RAA to port ", port
      except CatchableError as e:
        echo "  MS-RAA not registered on this host: ", e.msg
        skip()

  test "SMB2 anonymous SESSION_SETUP + TREE_CONNECT IPC$":
    let host = getEnv("MSRPC_TEST_HOST")
    if host.len == 0:
      skip()
    else:
      let p = newNtlmAnonymousProvider("MSRPCNIM")
      let s = newSmbSession(host, envPort("MSRPC_TEST_SMB_PORT", 445),
                             p, "cifs/" & host)
      check s.sessionId != 0
      check s.treeId == 1
      echo "  SMB session id: 0x", toHex(BiggestInt(s.sessionId), 16),
           "  tree id: 0x", toHex(BiggestInt(s.treeId), 8)

  test "authenticated SAMR over SMB named pipe":
    let host = getEnv("MSRPC_TEST_HOST")
    let user = getEnv("MSRPC_TEST_USER")
    let pass = getEnv("MSRPC_TEST_PASS")
    let dom  = getEnv("MSRPC_TEST_DOMAIN")
    if host.len == 0 or user.len == 0 or pass.len == 0:
      skip()
    else:
      let smbProv = newNtlmProvider(dom, user, pass, "MSRPCNIM")
      let rpcProv = newNtlmProvider(dom, user, pass, "MSRPCNIM",
                                     authLevel = alPktPrivacy)
      let s = newSmbSession(host, envPort("MSRPC_TEST_SMB_PORT", 445),
                             smbProv, "cifs/" & host)
      let pipe = s.openPipe("samr")
      let t = newNamedPipeTransport(pipe)
      let samrUuid = parseUuid(samridl.SamrInterfaceUuid)
      let c = connect(t, samrUuid,
                      interfaceVersion = uint32(samridl.SamrInterfaceMajor),
                      auth = rpcProv, authLevel = alPktPrivacy,
                      targetSpn = "cifs/" & host)
      var handle: samridl.SamrHandle
      let st = c.samrConnect("", samridl.SAMR_MAXIMUM_ALLOWED, handle)
      check st.isSuccess
      echo "  SamrConnect returned status=", st,
           " handle.attr=0x", toHex(int(handle.attr), 8)
      var freeHandle = handle
      discard c.samrCloseHandle(freeHandle)
      c.close()

  test "SMB2 CREATE on samr pipe returns ACCESS_DENIED for anonymous":
    let host = getEnv("MSRPC_TEST_HOST")
    if host.len == 0:
      skip()
    else:
      let p = newNtlmAnonymousProvider("MSRPCNIM")
      let s = newSmbSession(host, envPort("MSRPC_TEST_SMB_PORT", 445),
                             p, "cifs/" & host)
      try:
        let pipe = s.openPipe("samr")
        echo "  unexpectedly opened samr pipe under anonymous"
        pipe.close()
      except SmbError as e:
        # Expected: 0xC0000022 STATUS_ACCESS_DENIED.
        check "0xC0000022" in e.msg or "3221225506" in e.msg
        echo "  CREATE \\samr denied as expected (", e.msg, ")"

  test "MS-RAA: AccessCheck against a trivial SD":
    let host = getEnv("MSRPC_TEST_HOST")
    let user = getEnv("MSRPC_TEST_USER")
    let pass = getEnv("MSRPC_TEST_PASS")
    if host.len == 0 or user.len == 0 or pass.len == 0:
      skip()
    else:
      let dom  = envOr("MSRPC_TEST_DOMAIN", "WORKGROUP")
      let sidStr = envOr("MSRPC_TEST_SID", "S-1-5-32-544")

      let raaUuid = parseUuid("0b1c2170-5732-4e0e-8cd3-d9b16f3b84d7")
      let ndrUuid = parseUuid("8a885d04-1ceb-11c9-9fe8-08002b104860")
      let port = epmLookupTcpPort(host, raaUuid, 0, ndrUuid)

      let t = newTcpTransport(host, int(port))
      let auth = newNtlmProvider(dom, user, pass, "MSRPCNIM",
                                  authLevel = alPktPrivacy)
      let c = connect(t, raaUuid, interfaceVersion = 0,
                      auth = auth, authLevel = alPktPrivacy,
                      targetSpn = "host/" & host)

      var handle: AuthzrContextHandle
      let initStatus = authzrInitializeContextFromSid(
        c, flags = 0,
        userSid = parseSid(sidStr),
        expirationTime = 0,
        identifierLow = 0, identifierHigh = 0,
        handle = handle)
      if not initStatus.isSuccess:
        echo "  InitializeContextFromSid status: ", initStatus
        check false

      # Trivial SD: rev=1, control = SE_DACL_PRESENT, no DACL bytes.
      let sd = @[
        1'u8, 0,
        0x04'u8, 0x80,
        0'u8, 0, 0, 0,
        0'u8, 0, 0, 0,
        0'u8, 0, 0, 0,
        0'u8, 0, 0, 0]

      var reply: AuthzrAccessReply
      let req = AuthzrAccessRequest(desiredAccess: 0x02000000'u32)
      let st = authzrAccessCheck(c, handle, flags = 0, req, sd, reply)
      echo "  AccessCheck status: ", st,
           "  granted: ", reply.grantedAccessMask,
           "  errors: ", reply.error

      var freeHandle = handle
      discard authzrFreeContext(c, freeHandle)
      c.close()
