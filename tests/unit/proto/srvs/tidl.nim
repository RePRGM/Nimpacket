import std/unittest
import msrpc/proto/srvs/idl

suite "srvs constants and pretty-print":
  test "interface UUID matches MS-SRVS":
    check SrvsInterfaceUuid == "4b324fc8-1670-01d3-1278-5a47bf6ee188"
    check SrvsInterfaceMajor == 3

  test "share type pretty-print":
    check shareTypeName(STYPE_DISKTREE) == "DISK"
    check shareTypeName(STYPE_IPC) == "IPC"
    check shareTypeName(STYPE_DISKTREE or STYPE_SPECIAL) == "DISK,SPECIAL"
    check shareTypeName(STYPE_IPC or STYPE_SPECIAL) == "IPC,SPECIAL"
