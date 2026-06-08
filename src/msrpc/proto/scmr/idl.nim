## proto/scmr/idl.nim — MS-SCMR (Service Control Manager Remote Protocol).
##
## Interface: 367abb81-9844-35f1-ad32-98f038001003, version 2.0
## Pipe:      \svcctl
##
## Opnums implemented (the practically-useful slice):
##    0  RCloseServiceHandle
##    1  RControlService           start/stop/pause/continue
##    6  RQueryServiceStatus       fetch current state
##   14  REnumServicesStatusW      enumerate services on the SCM
##   15  ROpenSCManagerW           open the SCM database
##   16  ROpenServiceW             open a handle to a specific service

import ../../common/[buffers, endian, status, unicode]
import ../../ndr/[context, primitives]
import ../../rpc/client

const ScmrInterfaceUuid* = "367abb81-9844-35f1-ad32-98f038001003"
const ScmrInterfaceMajor* = 2'u16
const ScmrInterfaceMinor* = 0'u16

# --- 20-byte context handle ------------------------------------------

type
  ScHandle* = object
    attr*: uint32
    uuid*: array[16, byte]

proc marshal*(c: NdrContext; v: var ScHandle) =
  c.align(4)
  case c.dir
  of ndEncode:
    c.buf.writeU32LE(v.attr)
    for x in v.uuid: c.buf.writeByte(x)
  of ndDecode:
    v.attr = c.buf.readU32LE()
    for i in 0 ..< 16: v.uuid[i] = c.buf.readByte()

# --- Access masks (MS-SCMR §2.2.1) ----------------------------------

const
  SC_MANAGER_CONNECT*            = 0x00000001'u32
  SC_MANAGER_CREATE_SERVICE*     = 0x00000002'u32
  SC_MANAGER_ENUMERATE_SERVICE*  = 0x00000004'u32
  SC_MANAGER_LOCK*               = 0x00000008'u32
  SC_MANAGER_QUERY_LOCK_STATUS*  = 0x00000010'u32
  SC_MANAGER_MODIFY_BOOT_CONFIG* = 0x00000020'u32
  SC_MANAGER_ALL_ACCESS*         = 0x000F003F'u32

  SERVICE_QUERY_CONFIG*          = 0x00000001'u32
  SERVICE_CHANGE_CONFIG*         = 0x00000002'u32
  SERVICE_QUERY_STATUS*          = 0x00000004'u32
  SERVICE_ENUMERATE_DEPENDENTS*  = 0x00000008'u32
  SERVICE_START*                 = 0x00000010'u32
  SERVICE_STOP*                  = 0x00000020'u32
  SERVICE_PAUSE_CONTINUE*        = 0x00000040'u32
  SERVICE_INTERROGATE*           = 0x00000080'u32
  SERVICE_USER_DEFINED_CONTROL*  = 0x00000100'u32
  SERVICE_ALL_ACCESS*            = 0x000F01FF'u32

  SCMR_MAXIMUM_ALLOWED*          = 0x02000000'u32

# --- Service control codes (MS-SCMR §3.1.4.2) -----------------------

const
  SERVICE_CONTROL_STOP*         = 0x00000001'u32
  SERVICE_CONTROL_PAUSE*        = 0x00000002'u32
  SERVICE_CONTROL_CONTINUE*     = 0x00000003'u32
  SERVICE_CONTROL_INTERROGATE*  = 0x00000004'u32

# --- Service type / state masks for enumeration --------------------

const
  SERVICE_TYPE_KERNEL_DRIVER*       = 0x00000001'u32
  SERVICE_TYPE_FILE_SYSTEM_DRIVER*  = 0x00000002'u32
  SERVICE_TYPE_WIN32_OWN_PROCESS*   = 0x00000010'u32
  SERVICE_TYPE_WIN32_SHARE_PROCESS* = 0x00000020'u32
  SERVICE_TYPE_INTERACTIVE_PROCESS* = 0x00000100'u32
  SERVICE_TYPE_WIN32*               = 0x00000030'u32  # OWN_PROCESS|SHARE_PROCESS
  SERVICE_TYPE_DRIVER*              = 0x0000000B'u32

  SERVICE_STATE_ACTIVE*    = 0x00000001'u32
  SERVICE_STATE_INACTIVE*  = 0x00000002'u32
  SERVICE_STATE_ALL*       = 0x00000003'u32

# --- SERVICE_STATUS (28 bytes, all u32 fields) ----------------------

type
  ServiceStatus* = object
    serviceType*: uint32
    currentState*: uint32
    controlsAccepted*: uint32
    win32ExitCode*: uint32
    serviceSpecificExitCode*: uint32
    checkPoint*: uint32
    waitHint*: uint32

  CurrentState* = enum
    csStopped       = 1
    csStartPending  = 2
    csStopPending   = 3
    csRunning       = 4
    csContinuePending = 5
    csPausePending  = 6
    csPaused        = 7

proc marshal*(c: NdrContext; v: var ServiceStatus) =
  c.align(4)
  marshal(c, v.serviceType)
  marshal(c, v.currentState)
  marshal(c, v.controlsAccepted)
  marshal(c, v.win32ExitCode)
  marshal(c, v.serviceSpecificExitCode)
  marshal(c, v.checkPoint)
  marshal(c, v.waitHint)

proc `$`*(cs: CurrentState): string =
  case cs
  of csStopped: "STOPPED"
  of csStartPending: "START_PENDING"
  of csStopPending: "STOP_PENDING"
  of csRunning: "RUNNING"
  of csContinuePending: "CONTINUE_PENDING"
  of csPausePending: "PAUSE_PENDING"
  of csPaused: "PAUSED"

# --- helpers --------------------------------------------------------

proc writeUniquePwstr(b: Buffer; s: string; refIdBase: uint32 = 0x00020000) =
  ## Top-level unique pointer to a conformant-varying wide string with
  ## NUL terminator. ``""`` is encoded as the null pointer.
  if s.len == 0:
    b.writeU32LE(0)
    return
  b.writeU32LE(refIdBase)
  let units = toUtf16Units(s)
  let nUnits = units.len + 1   # include the NUL
  b.writeU32LE(uint32(nUnits)) # max_count
  b.writeU32LE(0)              # offset
  b.writeU32LE(uint32(nUnits)) # actual
  for u in units: b.writeU16LE(u)
  b.writeU16LE(0)              # NUL
  b.alignTo(4)

proc writeRefPwstr(b: Buffer; s: string) =
  ## Top-level *ref* pointer to a conformant-varying wide string.
  ## C706 §14.3.10: top-level ref pointers carry NO referent id —
  ## the data follows directly. (Embedded ref pointers DO have refids.)
  let units = toUtf16Units(s)
  let nUnits = units.len + 1
  b.writeU32LE(uint32(nUnits))
  b.writeU32LE(0)
  b.writeU32LE(uint32(nUnits))
  for u in units: b.writeU16LE(u)
  b.writeU16LE(0)
  b.alignTo(4)

# --- Opnum 15: ROpenSCManagerW --------------------------------------
#
# DWORD ROpenSCManagerW(
#   [in,unique,string] SVCCTL_HANDLEW lpMachineName,
#   [in,unique,string] wchar_t *lpDatabaseName,
#   [in] DWORD dwDesiredAccess,
#   [out] LPSC_RPC_HANDLE lpScHandle);

proc rOpenSCManagerW*(rpc: RpcClient; machineName, databaseName: string;
                      desiredAccess: uint32;
                      handle: var ScHandle): NtStatus =
  let c = newNdrEncode(nsNdr)
  c.buf.writeUniquePwstr(machineName, 0x00020000)
  c.buf.writeUniquePwstr(databaseName, 0x00020004)
  c.buf.writeU32LE(desiredAccess)
  let reply = rpc.call(opnum = 15, stub = c.finish())
  let dc = newNdrDecode(reply, nsNdr)
  marshal(dc, handle)
  var st: uint32
  marshal(dc, st)
  result = NtStatus(st)

# --- Opnum 16: ROpenServiceW ---------------------------------------
#
# DWORD ROpenServiceW(
#   [in] SC_RPC_HANDLE hSCManager,
#   [in,string] wchar_t *lpServiceName,
#   [in] DWORD dwDesiredAccess,
#   [out] LPSC_RPC_HANDLE lpServiceHandle);

proc rOpenServiceW*(rpc: RpcClient; scm: ScHandle; serviceName: string;
                    desiredAccess: uint32;
                    handle: var ScHandle): NtStatus =
  let c = newNdrEncode(nsNdr)
  var h = scm; marshal(c, h)
  c.buf.writeRefPwstr(serviceName)
  c.buf.writeU32LE(desiredAccess)
  let reply = rpc.call(opnum = 16, stub = c.finish())
  let dc = newNdrDecode(reply, nsNdr)
  marshal(dc, handle)
  var st: uint32
  marshal(dc, st)
  result = NtStatus(st)

# --- Opnum 0: RCloseServiceHandle ----------------------------------

proc rCloseServiceHandle*(rpc: RpcClient; handle: var ScHandle): NtStatus =
  let c = newNdrEncode(nsNdr)
  marshal(c, handle)
  let reply = rpc.call(opnum = 0, stub = c.finish())
  let dc = newNdrDecode(reply, nsNdr)
  marshal(dc, handle)
  var st: uint32
  marshal(dc, st)
  result = NtStatus(st)

# --- Opnum 6: RQueryServiceStatus ----------------------------------

proc rQueryServiceStatus*(rpc: RpcClient; svc: ScHandle;
                         status: var ServiceStatus): NtStatus =
  let c = newNdrEncode(nsNdr)
  var h = svc; marshal(c, h)
  let reply = rpc.call(opnum = 6, stub = c.finish())
  let dc = newNdrDecode(reply, nsNdr)
  marshal(dc, status)
  var st: uint32
  marshal(dc, st)
  result = NtStatus(st)

# --- Opnum 1: RControlService --------------------------------------

proc rControlService*(rpc: RpcClient; svc: ScHandle; control: uint32;
                     status: var ServiceStatus): NtStatus =
  let c = newNdrEncode(nsNdr)
  var h = svc; marshal(c, h)
  c.buf.writeU32LE(control)
  let reply = rpc.call(opnum = 1, stub = c.finish())
  let dc = newNdrDecode(reply, nsNdr)
  marshal(dc, status)
  var st: uint32
  marshal(dc, st)
  result = NtStatus(st)

# --- Opnum 14: REnumServicesStatusW --------------------------------
#
# DWORD REnumServicesStatusW(
#   [in] SC_RPC_HANDLE hSCManager,
#   [in] DWORD dwServiceType,
#   [in] DWORD dwServiceState,
#   [in,out,size_is(cbBufSize)] LPBYTE lpBuffer,
#   [in] DWORD cbBufSize,
#   [out] LPBOUNDED_DWORD_256K pcbBytesNeeded,
#   [out] LPBOUNDED_DWORD_256K lpServicesReturned,
#   [in,out,unique] LPBOUNDED_DWORD_256K lpResumeIndex);
#
# The output buffer contains a packed array of ENUM_SERVICE_STATUSW
# entries followed by their string buffers (with offsets relative to
# the start of the buffer). We unpack them post-hoc.

type
  ServiceEntry* = object
    serviceName*: string
    displayName*: string
    status*: ServiceStatus

proc rEnumServicesStatusW*(rpc: RpcClient; scm: ScHandle;
                            serviceType, serviceState: uint32;
                            bufSize: uint32;
                            services: var seq[ServiceEntry];
                            bytesNeeded: var uint32;
                            resumeIndex: var uint32): NtStatus =
  let c = newNdrEncode(nsNdr)
  var h = scm; marshal(c, h)
  c.buf.writeU32LE(serviceType)
  c.buf.writeU32LE(serviceState)
  # lpBuffer (in/out conformant array of bytes, size = bufSize)
  c.buf.writeU32LE(bufSize)    # conformance count
  for _ in 0 ..< int(bufSize): c.buf.writeByte(0)
  c.buf.writeU32LE(bufSize)
  # lpResumeIndex (unique pointer to DWORD)
  if resumeIndex == 0:
    c.buf.writeU32LE(0)
  else:
    c.buf.writeU32LE(0x00020000)
    c.buf.writeU32LE(resumeIndex)

  let reply = rpc.call(opnum = 14, stub = c.finish())
  let dc = newNdrDecode(reply, nsNdr)

  # lpBuffer OUT: conformant array of bytes, leading max_count
  let outMax = dc.buf.readU32LE()
  let outBuf = dc.buf.readBytes(int(outMax))
  dc.buf.alignTo(4)
  bytesNeeded = dc.buf.readU32LE()
  let servicesReturned = dc.buf.readU32LE()
  # ResumeIndex unique pointer (in/out)
  let resRef = dc.buf.readU32LE()
  if resRef != 0:
    resumeIndex = dc.buf.readU32LE()
  var st: uint32
  marshal(dc, st)
  result = NtStatus(st)

  # Unpack ENUM_SERVICE_STATUSW entries from outBuf. Each is:
  #   DWORD lpServiceNameOffset    (offset into outBuf to wide string)
  #   DWORD lpDisplayNameOffset
  #   DWORD dwServiceType
  #   DWORD dwCurrentState
  #   DWORD dwControlsAccepted
  #   DWORD dwWin32ExitCode
  #   DWORD dwServiceSpecificExitCode
  #   DWORD dwCheckPoint
  #   DWORD dwWaitHint
  # = 36 bytes per entry.
  services = @[]
  for i in 0 ..< int(servicesReturned):
    let base = i * 36
    if base + 36 > outBuf.len: break
    let nameOff =
      uint32(outBuf[base]) or
      (uint32(outBuf[base+1]) shl 8) or
      (uint32(outBuf[base+2]) shl 16) or
      (uint32(outBuf[base+3]) shl 24)
    let dispOff =
      uint32(outBuf[base+4]) or
      (uint32(outBuf[base+5]) shl 8) or
      (uint32(outBuf[base+6]) shl 16) or
      (uint32(outBuf[base+7]) shl 24)

    proc readWStringAt(off: uint32): string =
      var i = int(off)
      var units: seq[uint16] = @[]
      while i + 1 < outBuf.len:
        let u = uint16(outBuf[i]) or (uint16(outBuf[i+1]) shl 8)
        if u == 0: break
        units.add u; i += 2
      fromUtf16Units(units)

    var entry: ServiceEntry
    entry.serviceName = readWStringAt(nameOff)
    entry.displayName = readWStringAt(dispOff)
    entry.status.serviceType =
      uint32(outBuf[base+8]) or (uint32(outBuf[base+9]) shl 8) or
      (uint32(outBuf[base+10]) shl 16) or (uint32(outBuf[base+11]) shl 24)
    entry.status.currentState =
      uint32(outBuf[base+12]) or (uint32(outBuf[base+13]) shl 8) or
      (uint32(outBuf[base+14]) shl 16) or (uint32(outBuf[base+15]) shl 24)
    entry.status.controlsAccepted =
      uint32(outBuf[base+16]) or (uint32(outBuf[base+17]) shl 8) or
      (uint32(outBuf[base+18]) shl 16) or (uint32(outBuf[base+19]) shl 24)
    services.add entry
