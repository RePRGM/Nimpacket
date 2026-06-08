## ndr/structs.nim — helpers for hand-written struct marshalling.
##
## NDR struct alignment (C706 §14.3.7.1): a struct is aligned to the
## maximum alignment requirement of any of its members. Conformant
## structs (containing a trailing conformant array) place their
## conformance count *before* the struct body.
##
## We don't try to reflect-and-derive marshalling here; per-protocol
## stubs (e.g. proto/raa/idl.nim) define one ``marshal`` proc per
## struct using these helpers.

import context

template structAlign*(c: NdrContext; n: int) =
  ## Place at the start of every struct's marshal proc.
  c.align(n)

template structAlignNdr64*(c: NdrContext; ndrAlign, ndr64Align: int) =
  ## Convenience for structs whose alignment differs between syntaxes.
  case c.syntax
  of nsNdr: c.align(ndrAlign)
  of nsNdr64: c.align(ndr64Align)
