## SCMR byte-layout tests. Live correctness was confirmed against
## real Windows; these tests pin the byte layouts so regressions get
## caught before the next live run.

import std/[unittest, strutils]
import msrpc/common/buffers
import msrpc/ndr/[context, primitives]
import msrpc/proto/scmr/idl

proc hex(d: openArray[byte]): string =
  for b in d: result.add toHex(int(b), 2).toLowerAscii

suite "scmr constants":
  test "interface UUID":
    check ScmrInterfaceUuid == "367abb81-9844-35f1-ad32-98f038001003"
    check ScmrInterfaceMajor == 2
    check ScmrInterfaceMinor == 0

  test "access masks":
    check SC_MANAGER_CONNECT == 1
    check SERVICE_QUERY_STATUS == 4

  test "service control codes":
    check SERVICE_CONTROL_STOP == 1
    check SERVICE_CONTROL_PAUSE == 2
    check SERVICE_CONTROL_CONTINUE == 3
    check SERVICE_CONTROL_INTERROGATE == 4

suite "scmr ServiceStatus":
  test "marshal round-trip":
    let bytes = ndrEncode[ServiceStatus](ServiceStatus(
      serviceType: 0x10, currentState: 4, controlsAccepted: 0xC0,
      win32ExitCode: 0, serviceSpecificExitCode: 0,
      checkPoint: 0, waitHint: 0), nsNdr)
    check bytes.len == 28      # seven u32 fields
    let r = ndrDecode[ServiceStatus](bytes, nsNdr)
    check r.serviceType == 0x10
    check r.currentState == 4
    check r.controlsAccepted == 0xC0
