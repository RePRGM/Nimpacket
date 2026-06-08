import std/unittest
import msrpc/ndr/[context, primitives, unions]

suite "ndr unions":
  test "encapsulated union picks correct arm":
    let c = newNdrEncode(nsNdr)
    var disc: uint32 = 2
    marshalEncapsulatedUnion(c, disc, [
      (tag: 1'u32, m: UnionVariantProc(proc(c: NdrContext) =
        var v: uint32 = 0x111
        marshal(c, v))),
      (tag: 2'u32, m: UnionVariantProc(proc(c: NdrContext) =
        var v: uint32 = 0x222
        marshal(c, v)))])
    let bytes = c.finish()
    check bytes == @[2'u8,0,0,0, 0x22,0x02,0,0]

  test "non-encapsulated union without discriminator on wire":
    let c = newNdrEncode(nsNdr)
    marshalNonEncapsulatedUnion(c, 1'u32, [
      (tag: 1'u32, m: UnionVariantProc(proc(c: NdrContext) =
        var v: uint16 = 0xABCD
        marshal(c, v)))])
    check c.finish() == @[0xCD'u8, 0xAB]

  test "unknown tag raises":
    let c = newNdrEncode(nsNdr)
    var disc: uint32 = 99
    expect NdrError:
      marshalEncapsulatedUnion(c, disc, [
        (tag: 1'u32, m: UnionVariantProc(proc(c: NdrContext) = discard))])
