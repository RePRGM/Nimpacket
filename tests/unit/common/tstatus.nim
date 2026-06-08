import std/unittest
import msrpc/common/status

suite "status":
  test "severity bits":
    check STATUS_SUCCESS.isSuccess
    check (not STATUS_SUCCESS.isError)
    check STATUS_ACCESS_DENIED.isError
    check STATUS_INVALID_HANDLE.isError

  test "raiseIfError on success is no-op":
    raiseIfError(STATUS_SUCCESS, "noop")

  test "raiseIfError raises with code":
    try:
      raiseIfError(STATUS_ACCESS_DENIED, "test")
      check false
    except RpcError as e:
      check e.code == 0xC0000022'u32

  test "Win32Error raiseIfError":
    raiseIfError(ERROR_SUCCESS, "noop")
    try:
      raiseIfError(ERROR_ACCESS_DENIED, "w32")
      check false
    except RpcError as e:
      check e.code == 5

  test "stringification":
    check $STATUS_ACCESS_DENIED == "0xC0000022"
