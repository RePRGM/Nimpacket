## status.nim — NTSTATUS / Win32 / HRESULT helpers.
##
## MS-RAA returns DWORD status codes (Win32). Other protocols return
## NTSTATUS or HRESULT; all three fit in 32 bits.

import std/strutils

type
  NtStatus* = distinct uint32
  Win32Error* = distinct uint32
  HResult* = distinct uint32

  RpcError* = object of CatchableError
    code*: uint32

const
  STATUS_SUCCESS*           = NtStatus(0x00000000'u32)
  STATUS_INVALID_HANDLE*    = NtStatus(0xC0000008'u32)
  STATUS_ACCESS_DENIED*     = NtStatus(0xC0000022'u32)
  STATUS_INVALID_PARAMETER* = NtStatus(0xC000000D'u32)

  ERROR_SUCCESS*            = Win32Error(0)
  ERROR_ACCESS_DENIED*      = Win32Error(5)
  ERROR_INVALID_PARAMETER*  = Win32Error(87)

proc `==`*(a, b: NtStatus): bool {.borrow.}
proc `==`*(a, b: Win32Error): bool {.borrow.}
proc `==`*(a, b: HResult): bool {.borrow.}

proc value*(s: NtStatus):  uint32 {.inline.} = uint32(s)
proc value*(s: Win32Error): uint32 {.inline.} = uint32(s)
proc value*(s: HResult):   uint32 {.inline.} = uint32(s)

proc isSuccess*(s: NtStatus): bool {.inline.} = s.value == 0
proc isWarning*(s: NtStatus): bool {.inline.} = ((s.value shr 30) and 0b11) == 0b01
proc isError*(s: NtStatus):   bool {.inline.} = ((s.value shr 30) and 0b11) == 0b11

proc `$`*(s: NtStatus): string =
  result = "0x" & toHex(int(s.value), 8)

proc `$`*(s: Win32Error): string =
  result = "Win32(" & $s.value & ")"

proc `$`*(s: HResult): string =
  result = "HRESULT(0x" & toHex(int(s.value), 8) & ")"

proc raiseIfError*(s: NtStatus; ctx = "") =
  if s.isError:
    var e = newException(RpcError, ctx & " failed: " & $s)
    e.code = s.value
    raise e

proc raiseIfError*(s: Win32Error; ctx = "") =
  if s.value != 0:
    var e = newException(RpcError, ctx & " failed: " & $s)
    e.code = s.value
    raise e
