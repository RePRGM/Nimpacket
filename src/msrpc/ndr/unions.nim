## ndr/unions.nim — encapsulated and non-encapsulated unions.
##
## *Encapsulated* (C706 §14.3.8) unions wire-encode the discriminator
## immediately before the variant body, both at 4-byte alignment.
##
## *Non-encapsulated* unions take the discriminator from the surrounding
## struct/argument; only the variant body is on the wire here. The
## caller passes the discriminator value explicitly.

import context, primitives

type
  UnionVariantProc* = proc(c: NdrContext)

proc marshalEncapsulatedUnion*(c: NdrContext;
                               discriminator: var uint32;
                               variants: openArray[tuple[tag: uint32; m: UnionVariantProc]]) =
  c.align(4)
  marshal(c, discriminator)
  for v in variants:
    if v.tag == discriminator:
      v.m(c)
      return
  raise newException(NdrError, "unknown union discriminator: " & $discriminator)

proc marshalNonEncapsulatedUnion*(c: NdrContext;
                                  discriminator: uint32;
                                  variants: openArray[tuple[tag: uint32; m: UnionVariantProc]]) =
  for v in variants:
    if v.tag == discriminator:
      v.m(c)
      return
  raise newException(NdrError, "unknown union discriminator: " & $discriminator)
