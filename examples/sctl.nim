## examples/sctl.nim — query Windows services via MS-SCMR.
##
## Usage:
##   sctl status <ServiceName>      Query the current state
##   sctl enum                       Enumerate all services + state
##
## Both paths SMB-auth then open the \svcctl pipe with unauthenticated
## RPC over the SMB-authed channel.

import std/[os, strutils]
import msrpc/common/[guid, status]
import msrpc/auth/ntlm/provider
import msrpc/smb/client as smb
import msrpc/rpc/[client, transport_np]
import msrpc/proto/scmr/idl

let host = getEnv("MSRPC_TEST_HOST")
let user = getEnv("MSRPC_TEST_USER")
let pass = getEnv("MSRPC_TEST_PASS")
let dom  = getEnv("MSRPC_TEST_DOMAIN")
let mode = if paramCount() >= 1: paramStr(1) else: "enum"
let svcName = if paramCount() >= 2: paramStr(2) else: ""

if mode == "status" and svcName.len == 0:
  echo "usage: sctl status <ServiceName>"; quit(1)

let smbProv = newNtlmProvider(dom, user, pass, "MSRPCNIM")
let s = newSmbSession(host, 445, smbProv, "cifs/" & host)
let pipe = s.openPipe("svcctl")
let t = newNamedPipeTransport(pipe)
let rpc = connect(t, parseUuid(ScmrInterfaceUuid),
                  interfaceVersion = uint32(ScmrInterfaceMajor))

var scm: ScHandle
# CONNECT alone is granted to authenticated users on Windows; ENUM
# requires SC_MANAGER_ENUMERATE_SERVICE which is admin-only.
let wantedAccess =
  if mode == "enum": SC_MANAGER_CONNECT or SC_MANAGER_ENUMERATE_SERVICE
  else:              SC_MANAGER_CONNECT
let openSt = rpc.rOpenSCManagerW("", "", wantedAccess, scm)
if not openSt.isSuccess:
  echo "ROpenSCManagerW: ", openSt; quit(1)

case mode
of "status":
  var svc: ScHandle
  let oSt = rpc.rOpenServiceW(scm, svcName, SERVICE_QUERY_STATUS, svc)
  if not oSt.isSuccess:
    echo "ROpenServiceW(", svcName, "): ", oSt
  else:
    var sst: ServiceStatus
    let qSt = rpc.rQueryServiceStatus(svc, sst)
    if qSt.isSuccess:
      let state = CurrentState(sst.currentState)
      echo svcName, ":"
      echo "  state           : ", state, " (", sst.currentState, ")"
      echo "  service type    : 0x", toHex(int(sst.serviceType), 8)
      echo "  win32 exit code : ", sst.win32ExitCode
      echo "  service exit    : ", sst.serviceSpecificExitCode
      echo "  check point     : ", sst.checkPoint
      echo "  wait hint       : ", sst.waitHint
    else:
      echo "RQueryServiceStatus: ", qSt
    var sh = svc; discard rpc.rCloseServiceHandle(sh)

of "enum":
  var services: seq[ServiceEntry]
  var bytesNeeded, resumeIndex: uint32
  let eSt = rpc.rEnumServicesStatusW(scm,
              SERVICE_TYPE_WIN32 or SERVICE_TYPE_DRIVER,
              SERVICE_STATE_ALL, 64 * 1024,
              services, bytesNeeded, resumeIndex)
  if eSt.isSuccess or uint32(eSt) == 0x000000EA'u32:    # ERROR_MORE_DATA
    if uint32(eSt) == 0x000000EA:
      echo "[truncated, " & $bytesNeeded & " bytes needed for full list]"
    echo "Returned ", services.len, " service(s):"
    for e in services:
      let state = try: $CurrentState(e.status.currentState)
                  except CatchableError: "?"
      echo "  ", align(state, 16), "  ", align(e.serviceName, 32),
           "  ", e.displayName
  else:
    echo "REnumServicesStatusW: ", eSt
else:
  echo "unknown mode: ", mode

var sh = scm; discard rpc.rCloseServiceHandle(sh)
rpc.close()
