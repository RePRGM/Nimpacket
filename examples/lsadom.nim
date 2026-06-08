## examples/lsadom.nim — small utility that prints the local account
## domain SID and name on the target host, over MS-LSARPC.
##
## Build:   nim c examples/lsadom.nim
## Usage:   MSRPC_TEST_HOST=... MSRPC_TEST_USER=... ./lsadom

import std/[os, strutils]
import msrpc/common/[guid, sid, status]
import msrpc/auth/ntlm/provider
import msrpc/smb/client as smb
import msrpc/rpc/[client, transport_np, auth]
import msrpc/proto/lsarpc/idl

let host = getEnv("MSRPC_TEST_HOST")
let user = getEnv("MSRPC_TEST_USER")
let pass = getEnv("MSRPC_TEST_PASS")
let dom  = getEnv("MSRPC_TEST_DOMAIN")

doAssert host.len > 0, "set MSRPC_TEST_HOST"

let smbProv = newNtlmProvider(dom, user, pass, "MSRPCNIM")
let s = newSmbSession(host, 445, smbProv, "cifs/" & host)
let pipe = s.openPipe("lsarpc")
let t = newNamedPipeTransport(pipe)
let lsaUuid = parseUuid(LsarInterfaceUuid)
# Unauthenticated RPC on an SMB-authenticated pipe — Windows accepts
# this for read-only LSA operations.
let rpc = connect(t, lsaUuid, interfaceVersion = uint32(LsarInterfaceMajor))

var pol: LsarHandle
let openSt = rpc.lsarOpenPolicy2("", POLICY_VIEW_LOCAL_INFORMATION, pol)
if not openSt.isSuccess:
  echo "LsarOpenPolicy2 failed: ", openSt
  rpc.close()
  quit(1)
echo "Policy opened."

var info: PolicyAccountDomainInfo
let qSt = rpc.lsarQueryAccountDomain(pol, info)
if qSt.isSuccess:
  echo "Account domain name : ", info.domainName
  if info.hasSid:
    echo "Account domain SID  : ", info.domainSid
else:
  echo "QueryAccountDomain failed: ", qSt

var p2 = pol
discard rpc.lsarClose(p2)
rpc.close()
