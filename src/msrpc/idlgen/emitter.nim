## idlgen/emitter.nim — turn parsed IDL into Nim source.
##
## The emitter targets the existing NDR runtime (msrpc/ndr/*). For each
## struct it emits a Nim ``type`` and a ``marshal*`` proc; for each
## interface method it emits a thin client stub that calls
## ``RpcClient.call``.
##
## The generated code is intentionally a starting point — production
## protocols often need per-call tweaks the generator can't infer from
## IDL alone, so the output is meant to be checked in and edited by
## hand when needed.

import std/[strutils, strformat, tables, sets]
import ast

type
  Emitter* = ref object
    out_buf*: string
    structNames*: HashSet[string]
    knownStructs*: Table[string, IdlStruct]

proc newEmitter*(): Emitter =
  result = Emitter()
  result.structNames = initHashSet[string]()
  result.knownStructs = initTable[string, IdlStruct]()

proc emit(e: Emitter; s: string) {.inline.} = e.out_buf.add s
proc emitLn(e: Emitter; s: string = "") {.inline.} = e.out_buf.add s; e.out_buf.add "\n"

proc nimNameOfStruct*(idlName: string): string =
  ## Convert FOO_BAR → FooBar.
  result = ""
  var capNext = true
  for ch in idlName:
    if ch == '_':
      capNext = true
    else:
      if capNext: result.add ch.toUpperAscii else: result.add ch.toLowerAscii
      capNext = false

proc nimNameOfField*(idlName: string): string =
  ## FooBar → fooBar, Length → length.
  if idlName.len == 0: return ""
  result = $idlName[0].toLowerAscii & idlName[1 ..< idlName.len]

# --- type mapping ---------------------------------------------------

proc nimTypeOf*(e: Emitter; t: IdlType): string =
  case t.kind
  of tBuiltin:
    case t.name
    of "byte", "BYTE", "char", "BOOLEAN", "boolean": return "uint8"
    of "short", "SHORT": return "int16"
    of "WORD", "USHORT", "unsigned short": return "uint16"
    of "long", "LONG", "ACCESS_MASK", "NTSTATUS", "HRESULT", "BOOL": return "int32"
    of "DWORD", "ULONG", "unsigned long": return "uint32"
    of "hyper", "unsigned hyper": return "uint64"
    of "GUID", "UUID": return "Uuid"
    of "RPC_UNICODE_STRING": return "RpcUnicodeString"
    of "PRPC_SID", "RPC_SID": return "Sid"
    of "LPWSTR", "PWSTR": return "string"
    of "void": return "void"
    else: return t.name
  of tNamed:
    return nimNameOfStruct(t.name)
  of tPointer:
    let inner = e.nimTypeOf(t.target)
    if inner == "void": return "pointer"
    return "ref " & inner
  of tArray:
    let inner = e.nimTypeOf(t.element)
    return fmt"array[{t.size}, {inner}]"

# --- struct emission ------------------------------------------------

proc emitStruct*(e: Emitter; s: IdlStruct) =
  if s.fields.len == 0: return     # plain typedef alias — skip
  let nimName = nimNameOfStruct(s.name)
  if nimName in e.structNames: return
  e.structNames.incl nimName
  e.knownStructs[s.name] = s

  e.emitLn(fmt"# --- {s.name} ---")
  e.emitLn(fmt"type {nimName}* = object")
  for f in s.fields:
    let fName = nimNameOfField(f.name)
    let fTy = e.nimTypeOf(f.typ)
    e.emitLn(fmt"  {fName}*: {fTy}")
  e.emitLn()

  # Marshal proc — handles scalars, named-struct delegation, unique
  # pointers to structs, conformant arrays via size_is.
  e.emitLn(fmt"proc marshal*(c: NdrContext; v: var {nimName}) =")
  e.emitLn("  mixin marshal")
  for f in s.fields:
    let fName = nimNameOfField(f.name)
    let isUnique = hasAttr(f.attrs, aUnique) or hasAttr(f.attrs, aPtr)
    let isString = hasAttr(f.attrs, aString)
    case f.typ.kind
    of tBuiltin:
      case f.typ.name
      of "byte", "BYTE", "BOOLEAN", "boolean":
        e.emitLn(fmt"  marshal(c, v.{fName})")
      of "DWORD", "ULONG", "unsigned long", "ACCESS_MASK",
         "NTSTATUS", "HRESULT", "long", "LONG":
        e.emitLn(fmt"  marshal(c, v.{fName})")
      of "WORD", "USHORT", "short", "SHORT", "unsigned short":
        e.emitLn(fmt"  marshal(c, v.{fName})")
      of "hyper", "unsigned hyper":
        e.emitLn(fmt"  marshal(c, v.{fName})")
      of "GUID", "UUID":
        e.emitLn("  c.align(4)")
        e.emitLn(fmt"  case c.dir")
        e.emitLn(fmt"  of ndEncode: c.buf.writeWire(v.{fName})")
        e.emitLn(fmt"  of ndDecode: v.{fName} = guid.readWire(c.buf)")
      of "RPC_UNICODE_STRING":
        e.emitLn(fmt"  marshal(c, v.{fName})")
      of "LPWSTR", "PWSTR":
        if isUnique:
          e.emitLn(fmt"  # TODO: unique pointer to wide string for {f.name}")
          e.emitLn(fmt"  marshalEmbeddedUniquePointer(c, v.{fName})")
        else:
          e.emitLn(fmt"  marshalWideStringRaw(c, v.{fName})")
      else:
        e.emitLn(fmt"  # TODO: builtin {f.typ.name} for {f.name}")
        e.emitLn(fmt"  marshal(c, v.{fName})")
    of tNamed:
      e.emitLn(fmt"  marshal(c, v.{fName})")
    of tPointer:
      if isUnique:
        e.emitLn(fmt"  marshalEmbeddedUniquePointer(c, v.{fName})")
      else:
        e.emitLn(fmt"  marshalEmbeddedRefPointer(c, v.{fName})")
    of tArray:
      e.emitLn(fmt"  marshalFixedArray(c, v.{fName})")
  e.emitLn()

# --- method emission ------------------------------------------------

proc emitMethod*(e: Emitter; m: IdlMethod) =
  let methodNimName = if m.name.len > 0:
    m.name[0].toLowerAscii & m.name[1 ..< m.name.len]
  else: ""
  e.emitLn(fmt"# Opnum {m.opnum} — {m.name}")
  e.emit(fmt"proc {methodNimName}*(rpc: RpcClient")
  for p in m.params:
    if hasAttr(p.attrs, aOut) and not hasAttr(p.attrs, aIn):
      e.emit(fmt"; {nimNameOfField(p.name)}: var {e.nimTypeOf(p.typ)}")
    elif hasAttr(p.attrs, aIn) and hasAttr(p.attrs, aOut):
      e.emit(fmt"; {nimNameOfField(p.name)}: var {e.nimTypeOf(p.typ)}")
    else:
      e.emit(fmt"; {nimNameOfField(p.name)}: {e.nimTypeOf(p.typ)}")
  let retTy = e.nimTypeOf(m.returnType)
  if retTy == "void":
    e.emitLn(") =")
  else:
    e.emitLn(fmt"): {retTy} =")
  e.emitLn("  ## Auto-generated stub. Marshal IN params, call, demarshal OUT.")
  e.emitLn("  let nc = newNdrEncode(nsNdr)")
  for p in m.params:
    if not hasAttr(p.attrs, aOut) or hasAttr(p.attrs, aIn):
      e.emitLn(fmt"  var {nimNameOfField(p.name)}_local = {nimNameOfField(p.name)}")
      e.emitLn(fmt"  marshal(nc, {nimNameOfField(p.name)}_local)")
  e.emitLn(fmt"  let reply = rpc.call(opnum = {m.opnum}, stub = nc.finish())")
  if retTy != "void":
    e.emitLn("  let dc = newNdrDecode(reply, nsNdr)")
    for p in m.params:
      if hasAttr(p.attrs, aOut):
        e.emitLn(fmt"  marshal(dc, {nimNameOfField(p.name)})")
    e.emitLn(fmt"  var retVal: {retTy}")
    e.emitLn("  marshal(dc, retVal)")
    e.emitLn("  result = retVal")
  e.emitLn()

# --- top level ------------------------------------------------------

proc emitInterface*(e: Emitter; iface: IdlInterface) =
  e.emitLn(fmt"## Auto-generated bindings for {iface.name}")
  e.emitLn("##")
  e.emitLn("## Generator: msrpc/idlgen. Edit the IDL source and re-generate,")
  e.emitLn("## or check this file in and tune by hand for the inevitable")
  e.emitLn("## cases the heuristic encoder doesn't get right.")
  e.emitLn()
  e.emitLn("import msrpc/common/[buffers, endian, guid, sid, status, unicode]")
  e.emitLn("import msrpc/ndr/[context, primitives, arrays, strings, pointers]")
  e.emitLn("import msrpc/rpc/client")
  e.emitLn()
  for a in iface.attrs:
    case a.kind
    of aUuid:
      if a.args.len > 0:
        e.emitLn(fmt"""const InterfaceUuid* = "{a.args[0]}"""")
    of aVersion:
      if a.args.len > 0:
        let v = a.args[0].split(".")
        if v.len >= 2:
          e.emitLn(fmt"const InterfaceMajor* = {v[0]}'u16")
          e.emitLn(fmt"const InterfaceMinor* = {v[1]}'u16")
    else: discard
  e.emitLn()
  for s in iface.structs:
    e.emitStruct(s)
  for m in iface.methods:
    e.emitMethod(m)

proc emitAll*(e: Emitter; ifaces: seq[IdlInterface]): string =
  for iface in ifaces:
    e.emitInterface(iface)
  result = e.out_buf
