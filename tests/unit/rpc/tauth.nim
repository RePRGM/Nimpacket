import std/unittest
import msrpc/common/buffers
import msrpc/rpc/auth

suite "rpc sec_trailer":
  test "round-trip":
    let t = SecTrailer(authType: atNtlm, authLevel: alPktPrivacy,
                       padLength: 6, reserved: 0, contextId: 1)
    let b = newBuffer()
    b.writeSecTrailer(t)
    check b.consumed.len == SecTrailerLen
    let r = newBuffer(b.consumed)
    check r.readSecTrailer() == t

  test "wire layout":
    let t = SecTrailer(authType: atNtlm, authLevel: alPktPrivacy,
                       padLength: 4, reserved: 0, contextId: 0x12345678)
    let b = newBuffer()
    b.writeSecTrailer(t)
    # 10, 5, 4, 0, then LE u32
    check b.consumed == @[
      10'u8, 5, 4, 0,
      0x78, 0x56, 0x34, 0x12]

  test "auth level / type enum coverage":
    for lvl in AuthnLevel.low .. AuthnLevel.high:
      let t = SecTrailer(authType: atNtlm, authLevel: lvl,
                         padLength: 0, reserved: 0, contextId: 0)
      let b = newBuffer()
      b.writeSecTrailer(t)
      check newBuffer(b.consumed).readSecTrailer() == t
