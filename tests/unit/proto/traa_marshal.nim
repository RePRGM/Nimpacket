import std/unittest
import msrpc/common/[buffers, guid]
import msrpc/ndr/context
import msrpc/proto/raa/[types, idl]

suite "ms-raa marshalling":
  test "AuthzrContextHandle round-trip":
    var h = AuthzrContextHandle(
      handleAttr: 0,
      handleUuid: parseUuid("11223344-5566-7788-99aa-bbccddeeff00"))
    let c = newNdrEncode(nsNdr)
    marshal(c, h)
    let bytes = c.finish()
    check bytes.len == 4 + 16  # u32 + uuid wire

    let dc = newNdrDecode(bytes, nsNdr)
    var h2: AuthzrContextHandle
    marshal(dc, h2)
    check h2.handleAttr == h.handleAttr
    check h2.handleUuid == h.handleUuid

  test "ObjectTypeListEntry round-trip":
    var e = ObjectTypeListEntry(
      level: 1, sbz: 0, accessMask: 0x000F0001'u32,
      objectType: parseUuid("ab721a53-1e2f-11d0-9819-00aa0040529b"))
    let c = newNdrEncode(nsNdr)
    marshal(c, e)
    let bytes = c.finish()
    check bytes.len == 2 + 2 + 4 + 16

    let dc = newNdrDecode(bytes, nsNdr)
    var e2: ObjectTypeListEntry
    marshal(dc, e2)
    check e2 == e

  test "interface uuid constant matches MS-RAA":
    check RaaInterfaceUuid == "0b1c2170-5732-4e0e-8cd3-d9b16f3b84d7"
    check RaaInterfaceMajor == 0
    check RaaInterfaceMinor == 0

suite "AuthzrAccessCheck encoder":
  test "minimal stub (null sid, no OTL, no opt args)":
    var h = AuthzrContextHandle(
      handleAttr: 0,
      handleUuid: parseUuid("11223344-5566-7788-99aa-bbccddeeff00"))
    let sd = @[1'u8, 0, 4, 128, 0, 0, 0, 0]   # toy SD; opaque to our encoder
    let stub = buildAccessCheckStub(
      h, flags = 0,
      desiredAccess = 0x02000000'u32,           # MAXIMUM_ALLOWED
      principalSelfSid = nil,
      objectTypeList = [],
      optionalArguments = [],
      securityDescriptor = sd)
    # 20-byte handle then u32 flags then access_request.
    check stub[0..3] == @[0'u8, 0, 0, 0]   # handleAttr
    check stub.len > 20 + 4 + 24 + sd.len  # rough size assertion

  test "reply parser pulls grantedAccessMask out":
    # Build a synthetic reply: pReply = ResultListLength=1, three
    # unique pointers, each pointing to a 1-element u32 array.
    let b = newBuffer()
    b.writeBytes([1'u8, 0, 0, 0])         # ResultListLength = 1
    # GrantedAccessMask ptr
    b.writeBytes([0'u8, 0, 2, 0])         # refid non-null
    b.writeBytes([1'u8, 0, 0, 0])         # max_count = 1
    b.writeBytes([0xFF'u8, 0xFF, 0x1F, 0]) # mask = 0x001FFFFF
    # SaclEvaluationResults ptr — null
    b.writeBytes([0'u8, 0, 0, 0])
    # Error ptr
    b.writeBytes([0'u8, 0, 2, 0])
    b.writeBytes([1'u8, 0, 0, 0])
    b.writeBytes([0'u8, 0, 0, 0])         # error = 0 (success)
    # Trailing call status
    b.writeBytes([0'u8, 0, 0, 0])
    let reply = parseAccessCheckReply(b.consumed)
    check reply.resultListLength == 1
    check reply.grantedAccessMask.len == 1
    check reply.grantedAccessMask[0] == 0x001FFFFF'u32
    check reply.saclEvaluationResults.len == 0
    check reply.error == @[0'u32]
