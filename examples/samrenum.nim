## examples/samrenum.nim — list users in the local SAM via MS-SAMR.
##
## Flow:
##   1. SMB session + open \samr
##   2. SamrConnect5 (server handle)
##   3. SamrEnumerateDomainsInSamServer  → ["Builtin", "DESKTOP-..."]
##   4. SamrLookupDomainInSamServer       → domain SID
##   5. SamrOpenDomain                    → domain handle
##   6. SamrEnumerateUsersInDomain        → (RID, name) entries
##   7. cleanup
##
## Each call prints status — on the share user this will hit
## ACCESS_DENIED at the SamrConnect5 step, but every encoder is
## exercised. Re-run with admin creds for real output.

import std/[os, strutils]
import msrpc/common/[guid, sid, status]
import msrpc/auth/ntlm/provider
import msrpc/smb/client as smb
import msrpc/rpc/[client, transport_np, auth]
import msrpc/proto/samr/idl

let host = getEnv("MSRPC_TEST_HOST")
let user = getEnv("MSRPC_TEST_USER")
let pass = getEnv("MSRPC_TEST_PASS")
let dom  = getEnv("MSRPC_TEST_DOMAIN")
let useAuth = getEnv("MSRPC_NO_AUTH") == ""

let smbProv = newNtlmProvider(dom, user, pass, "MSRPCNIM")
let s = newSmbSession(host, 445, smbProv, "cifs/" & host)
let pipe = s.openPipe("samr")
let t = newNamedPipeTransport(pipe)
let samrUuid = parseUuid(SamrInterfaceUuid)

let rpc =
  if useAuth:
    let rpcProv = newNtlmProvider(dom, user, pass, "MSRPCNIM",
                                   authLevel = alPktIntegrity)
    connect(t, samrUuid, interfaceVersion = uint32(SamrInterfaceMajor),
            auth = rpcProv, authLevel = alPktIntegrity,
            targetSpn = "cifs/" & host)
  else:
    connect(t, samrUuid, interfaceVersion = uint32(SamrInterfaceMajor))

proc bail(call, st: string) =
  echo "[fail] ", call, ": ", st
  rpc.close()
  quit(1)

echo "[1] SamrConnect5(MAXIMUM_ALLOWED) ..."
var srv: SamrHandle
try:
  let s1 = rpc.samrConnect5("", SAMR_MAXIMUM_ALLOWED, srv)
  if not s1.isSuccess: bail("SamrConnect5", $s1)
  echo "    OK  handle uuid prefix=", toHex(int(srv.uuid[0]), 2),
       toHex(int(srv.uuid[1]), 2), toHex(int(srv.uuid[2]), 2),
       toHex(int(srv.uuid[3]), 2)
except CatchableError as e:
  echo "    [", e.msg, "]"
  echo "    (this is the expected outcome for non-admin users — re-run"
  echo "     with an account that has SAM_SERVER_CONNECT rights)"
  rpc.close(); quit(0)

echo "[2] SamrEnumerateDomainsInSamServer ..."
var ctx: uint32 = 0
var domsRes: EnumerateResult
let s2 = rpc.samrEnumerateDomainsInSamServer(srv, ctx, 0x10000'u32, domsRes)
if not s2.isSuccess: bail("EnumerateDomains", $s2)
echo "    found ", domsRes.entries.len, " domain(s):"
for d in domsRes.entries:
  echo "      ", d.name

# Pick the non-Builtin domain (the local account domain).
var pickedName = ""
for d in domsRes.entries:
  if d.name != "Builtin":
    pickedName = d.name; break
if pickedName.len == 0:
  echo "no account domain found"; rpc.close(); quit(1)
echo "[3] SamrLookupDomainInSamServer(", pickedName, ") ..."
var domSid: Sid
let s3 = rpc.samrLookupDomainInSamServer(srv, pickedName, domSid)
if not s3.isSuccess: bail("LookupDomain", $s3)
echo "    SID: ", domSid

echo "[4] SamrOpenDomain ..."
var domH: SamrHandle
let s4 = rpc.samrOpenDomain(srv, SAMR_MAXIMUM_ALLOWED, domSid, domH)
if not s4.isSuccess: bail("OpenDomain", $s4)
echo "    OK"

echo "[5] SamrEnumerateUsersInDomain ..."
var uctx: uint32 = 0
var usersRes: EnumerateResult
let s5 = rpc.samrEnumerateUsersInDomain(domH, uctx, 0, 0x10000'u32, usersRes)
if not s5.isSuccess: bail("EnumerateUsers", $s5)
echo "    ", usersRes.entries.len, " user(s):"
for u in usersRes.entries:
  echo "      RID ", align($u.rid, 5), "  ", u.name

# Cleanup
var dh = domH; discard rpc.samrCloseHandle(dh)
var sh = srv; discard rpc.samrCloseHandle(sh)
rpc.close()
