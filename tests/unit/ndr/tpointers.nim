import std/unittest
import msrpc/common/buffers
import msrpc/ndr/[context, primitives, pointers]

suite "ndr pointers":
  test "top-level unique pointer non-null":
    let c = newNdrEncode(nsNdr)
    var p: ref uint32
    new p
    p[] = 0xCAFEBABE'u32
    marshalTopUniquePointer(c, p)
    c.drainDeferred()
    let bytes = c.finish()
    # u32 referent id (non-zero) then aligned u32 payload
    check bytes.len == 8
    check bytes[4..7] == @[0xBE'u8, 0xBA, 0xFE, 0xCA]
    check (bytes[0] != 0'u8 or bytes[1] != 0'u8 or
           bytes[2] != 0'u8 or bytes[3] != 0'u8)

    let dc = newNdrDecode(bytes, nsNdr)
    var p2: ref uint32
    marshalTopUniquePointer(dc, p2)
    dc.drainDeferred()
    check p2 != nil
    check p2[] == 0xCAFEBABE'u32

  test "top-level unique pointer null":
    let c = newNdrEncode(nsNdr)
    var p: ref uint32 = nil
    marshalTopUniquePointer(c, p)
    c.drainDeferred()
    check c.finish() == @[0'u8, 0, 0, 0]

    let dc = newNdrDecode(@[0'u8,0,0,0], nsNdr)
    var p2: ref uint32
    marshalTopUniquePointer(dc, p2)
    dc.drainDeferred()
    check p2 == nil

  test "embedded unique pointer defers payload":
    let c = newNdrEncode(nsNdr)
    var p: ref uint32
    new p
    p[] = 0x11'u32
    marshalEmbeddedUniquePointer(c, p)
    # before draining: only the referent id is written
    let preDrain = c.buf.consumed
    check preDrain.len == 4
    c.drainDeferred()
    let bytes = c.finish()
    check bytes.len == 8
    check bytes[4..7] == @[0x11'u8, 0, 0, 0]

  test "embedded ref pointer raises when nil on encode":
    let c = newNdrEncode(nsNdr)
    var p: ref uint32 = nil
    expect NdrError:
      marshalEmbeddedRefPointer(c, p)
