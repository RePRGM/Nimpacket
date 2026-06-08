## examples/lsausers.nim — list local Windows users by translating SIDs.
##
## Flow:
##   1. SMB session + open \lsarpc
##   2. LsarOpenPolicy2 (unauthenticated RPC over SMB-auth'd pipe)
##   3. LsarQueryInformationPolicy(PolicyAccountDomainInformation)
##      → get the local SAM domain SID
##   4. Append common RIDs (500=Administrator, 501=Guest, 1000..1010
##      typical local user range) and call LsarLookupSids on each
##   5. Print whatever the server actually maps

import std/[os, strutils]
import msrpc/common/[guid, sid, status]
import msrpc/auth/ntlm/provider
import msrpc/smb/client as smb
import msrpc/rpc/[client, transport_np]
import msrpc/proto/lsarpc/idl

let host = getEnv("MSRPC_TEST_HOST")
let user = getEnv("MSRPC_TEST_USER")
let pass = getEnv("MSRPC_TEST_PASS")
let dom  = getEnv("MSRPC_TEST_DOMAIN")

let smbProv = newNtlmProvider(dom, user, pass, "MSRPCNIM")
let s = newSmbSession(host, 445, smbProv, "cifs/" & host)
let pipe = s.openPipe("lsarpc")
let t = newNamedPipeTransport(pipe)

let lsaUuid = parseUuid(LsarInterfaceUuid)
let rpc = connect(t, lsaUuid, interfaceVersion = uint32(LsarInterfaceMajor))

# Open with both VIEW and LOOKUP rights.
var pol: LsarHandle
let openSt = rpc.lsarOpenPolicy2("",
  POLICY_VIEW_LOCAL_INFORMATION or POLICY_LOOKUP_NAMES, pol)
if not openSt.isSuccess:
  echo "LsarOpenPolicy2 failed: ", openSt
  quit(1)

# Step 1: get the local account-domain SID.
var info: PolicyAccountDomainInfo
let qSt = rpc.lsarQueryAccountDomain(pol, info)
if not qSt.isSuccess:
  echo "QueryInformationPolicy failed: ", qSt
  quit(1)
echo "Local domain: ", info.domainName
echo "Local SID:    ", info.domainSid
echo ""

# Step 2: build SIDs for well-known + first 20 local-user RIDs.
let ridsOfInterest = block:
  var r = @[500'u32, 501, 503, 504]   # Administrator, Guest, DefaultAccount, WDAGUtilityAccount
  for rid in 1000'u32 .. 1020'u32: r.add rid
  r

var sids: seq[Sid] = @[]
for rid in ridsOfInterest:
  var s = info.domainSid
  s.subAuthority.add rid
  sids.add s

# Step 3: bulk lookup.
var res: LookupSidsResult
let lkSt = rpc.lsarLookupSids(pol, sids, res)

# Status is usually STATUS_SOME_NOT_MAPPED (0x00000107) when some RIDs
# don't exist; that's a SUCCESS-class warning per MS-LSAT.
echo "Lookup status: 0x", toHex(int64(uint32(lkSt)), 8)
echo ""
echo "Referenced domains:"
for i, dname in res.domains:
  echo "  [", i, "] ", dname
echo ""
echo "RID translations:"
for i, rid in ridsOfInterest:
  if i < res.names.len:
    let n = res.names[i]
    let domName = if n.domainIndex >= 0 and n.domainIndex < res.domains.len:
                    res.domains[n.domainIndex] else: "?"
    let kind = case n.sidUse
               of 1: "User"
               of 2: "Group"
               of 3: "Domain"
               of 4: "Alias"
               of 5: "Well-known"
               of 6: "DeletedAccount"
               of 7: "Invalid"
               of 8: "Unknown"
               else: $n.sidUse
    if n.name.len > 0:
      echo "  RID ", align($rid, 5), " : ", domName, "\\", n.name,
           " (", kind, ")"
    else:
      echo "  RID ", align($rid, 5), " : <unmapped>"

var p2 = pol
discard rpc.lsarClose(p2)
rpc.close()
