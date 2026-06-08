import std/unittest
import msrpc/ndr/[context, primitives, arrays]

suite "ndr arrays — NDR3":
  test "fixed array":
    let c = newNdrEncode(nsNdr)
    var arr = [1'u32, 2, 3]
    marshalFixedArray(c, arr)
    let bytes = c.finish()
    check bytes == @[1'u8,0,0,0, 2,0,0,0, 3,0,0,0]
    var out2: array[3, uint32]
    let dc = newNdrDecode(bytes, nsNdr)
    marshalFixedArray(dc, out2)
    check out2 == [1'u32, 2, 3]

  test "conformant array (header is u32 in NDR3)":
    let c = newNdrEncode(nsNdr)
    var arr = @[10'u32, 20, 30]
    marshalConformantArray(c, arr)
    let bytes = c.finish()
    # 4-byte max_count then three u32 values
    check bytes == @[3'u8,0,0,0, 10,0,0,0, 20,0,0,0, 30,0,0,0]
    var out2: seq[uint32]
    let dc = newNdrDecode(bytes, nsNdr)
    marshalConformantArray(dc, out2)
    check out2 == @[10'u32, 20, 30]

  test "varying array":
    let c = newNdrEncode(nsNdr)
    var arr = @[7'u16, 8, 9]
    var off: uint64 = 0
    var cnt: uint64 = 3
    marshalVaryingArray(c, arr, off, cnt)
    let bytes = c.finish()
    # offset u32, actual u32, then 3 u16s (with required 2-byte alignment satisfied)
    check bytes == @[0'u8,0,0,0, 3,0,0,0, 7,0, 8,0, 9,0]

  test "conformant-varying array":
    let c = newNdrEncode(nsNdr)
    var arr = @[100'u32, 200]
    var mc: uint64 = 2
    var off: uint64 = 0
    var cnt: uint64 = 2
    marshalConformantVaryingArray(c, arr, mc, off, cnt)
    let bytes = c.finish()
    check bytes == @[2'u8,0,0,0, 0,0,0,0, 2,0,0,0,
                     100,0,0,0, 200,0,0,0]

  test "conformant array empty":
    let c = newNdrEncode(nsNdr)
    var arr: seq[uint32] = @[]
    marshalConformantArray(c, arr)
    check c.finish() == @[0'u8, 0, 0, 0]
    var out2: seq[uint32]
    let dc = newNdrDecode(@[0'u8,0,0,0], nsNdr)
    marshalConformantArray(dc, out2)
    check out2.len == 0

suite "ndr arrays — NDR64":
  test "conformant array header is u64":
    let c = newNdrEncode(nsNdr64)
    var arr = @[42'u32]
    marshalConformantArray(c, arr)
    let bytes = c.finish()
    check bytes == @[1'u8,0,0,0,0,0,0,0,    # u64 max_count
                     42,0,0,0]
    var out2: seq[uint32]
    let dc = newNdrDecode(bytes, nsNdr64)
    marshalConformantArray(dc, out2)
    check out2 == @[42'u32]
