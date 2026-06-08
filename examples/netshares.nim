## examples/netshares.nim — list network shares on a Windows host.
##
## What ``net view \\host`` does, but cross-platform and dependency-free.

import std/[os, strutils]
import msrpc/common/[guid, status]
import msrpc/auth/ntlm/provider
import msrpc/smb/client as smb
import msrpc/rpc/[client, transport_np]
import msrpc/proto/srvs/idl

let host = getEnv("MSRPC_TEST_HOST")
let user = getEnv("MSRPC_TEST_USER")
let pass = getEnv("MSRPC_TEST_PASS")
let dom  = getEnv("MSRPC_TEST_DOMAIN")

let smbProv = newNtlmProvider(dom, user, pass, "MSRPCNIM")
let s = newSmbSession(host, 445, smbProv, "cifs/" & host)
let pipe = s.openPipe("srvsvc")
let t = newNamedPipeTransport(pipe)
let rpc = connect(t, parseUuid(SrvsInterfaceUuid),
                  interfaceVersion = uint32(SrvsInterfaceMajor))

var shares: seq[ShareInfo1]
var total, resume: uint32 = 0
let st = rpc.netrShareEnum("", 0xFFFFFFFF'u32, shares, total, resume)
if not st.isSuccess and uint32(st) != 0x00000000'u32 and
   uint32(st) != 0x000000EA'u32:           # ERROR_MORE_DATA is fine
  echo "NetrShareEnum: ", st
  rpc.close()
  quit(1)

echo "Shares on ", host, " (", shares.len, " of ", total, "):"
echo "  ", align("NAME", 24), " ", align("TYPE", 14), "  COMMENT"
echo "  ", repeat("-", 24), " ", repeat("-", 14), "  ", repeat("-", 30)
for sh in shares:
  echo "  ", align(sh.netname, 24), " ", align(shareTypeName(sh.shareType), 14),
       "  ", sh.remark
rpc.close()
