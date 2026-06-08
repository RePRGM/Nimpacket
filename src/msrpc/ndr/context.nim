## ndr/context.nim — NDR encode/decode context.
##
## A single ``NdrContext`` covers both directions (``dir``) and both
## transfer syntaxes (``syntax``). The per-type ``marshal`` procs branch
## on these fields, so a struct only needs one definition to support
## NDR3 + NDR64 encode + decode.
##
## Deferred-pointer queue (C706 §14.3.12.3): NDR places referent data
## for pointers embedded in structs after the containing struct's body.
## We model that by appending procs to ``deferred`` while marshalling
## the outer struct, then draining the queue at well-defined points.

import std/tables
import ../common/buffers

type
  NdrSyntax* = enum
    nsNdr      ## DCE NDR (C706), 4-byte conformance counts
    nsNdr64    ## MS-RPCE §2.2.5, 8-byte conformance counts

  NdrDir* = enum
    ndEncode
    ndDecode

  NdrError* = object of CatchableError

  Deferred* = proc(c: NdrContext) {.closure.}

  NdrContext* = ref object
    buf*: Buffer
    syntax*: NdrSyntax
    dir*: NdrDir
    nextRefId*: uint32                ## next embedded-pointer referent id
    deferred*: seq[Deferred]          ## NDR deferred-pointer queue
    seenRefIds*: Table[uint32, bool]  ## full-pointer alias detection (encode)
    refIdValues*: Table[uint32, pointer] ## decode-side alias map (opt-in)

proc newNdrEncode*(syntax = nsNdr): NdrContext =
  result = NdrContext(
    buf: newBuffer(),
    syntax: syntax,
    dir: ndEncode,
    nextRefId: 0x00020000'u32,        ## convention used by stub generators
    deferred: @[],
    seenRefIds: initTable[uint32, bool](),
    refIdValues: initTable[uint32, pointer]())

proc newNdrDecode*(data: openArray[byte]; syntax = nsNdr): NdrContext =
  result = NdrContext(
    buf: newBuffer(data),
    syntax: syntax,
    dir: ndDecode,
    nextRefId: 0x00020000'u32,
    deferred: @[],
    seenRefIds: initTable[uint32, bool](),
    refIdValues: initTable[uint32, pointer]())

proc newNdrDecode*(buf: Buffer; syntax = nsNdr): NdrContext =
  result = NdrContext(
    buf: buf,
    syntax: syntax,
    dir: ndDecode,
    nextRefId: 0x00020000'u32,
    deferred: @[],
    seenRefIds: initTable[uint32, bool](),
    refIdValues: initTable[uint32, pointer]())

proc finish*(c: NdrContext): seq[byte] =
  ## Return the encoded bytes (encode contexts) or the unconsumed
  ## remainder (decode contexts).
  case c.dir
  of ndEncode: c.buf.consumed
  of ndDecode: c.buf.readBytes(c.buf.remaining)

# --- alignment ------------------------------------------------------------

proc align*(c: NdrContext; n: int) {.inline.} = c.buf.alignTo(n)

proc pos*(c: NdrContext): int {.inline.} = c.buf.pos

# --- deferred queue --------------------------------------------------------

proc pushDeferred*(c: NdrContext; p: Deferred) {.inline.} =
  c.deferred.add p

proc drainDeferred*(c: NdrContext) =
  ## Run every queued deferred-pointer routine. Routines may queue more.
  while c.deferred.len > 0:
    let next = c.deferred[0]
    c.deferred.delete(0)
    next(c)

# --- referent id allocation -----------------------------------------------

proc allocRefId*(c: NdrContext): uint32 =
  result = c.nextRefId
  c.nextRefId += 4'u32
