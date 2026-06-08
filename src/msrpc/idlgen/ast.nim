## idlgen/ast.nim — AST nodes for the IDL subset we handle.

type
  IdlAttrKind* = enum
    aIn, aOut, aRef, aUnique, aPtr, aString, aContextHandle,
    aSizeIs, aLengthIs, aFirstIs, aMaxIs, aSwitchIs, aSwitchType, aRange,
    aV1Enum, aUuid, aVersion, aPointerDefault, aLocal, aObject, aEndpoint,
    aId, aHelpString, aRestricted, aImport

  IdlAttr* = object
    kind*: IdlAttrKind
    args*: seq[string]      ## raw text args (e.g. ["Count"] for size_is(Count))

  IdlTypeKind* = enum
    tBuiltin,    ## byte, short, long, hyper, DWORD, etc.
    tNamed,      ## a typedef name we've seen
    tPointer,    ## ptr to another type
    tArray,      ## C-style fixed array (rare in IDL)

  IdlType* = ref object
    case kind*: IdlTypeKind
    of tBuiltin, tNamed: name*: string
    of tPointer: target*: IdlType
    of tArray:
      element*: IdlType
      size*: int

  IdlField* = object
    name*: string
    typ*: IdlType
    attrs*: seq[IdlAttr]

  IdlStruct* = object
    name*: string
    fields*: seq[IdlField]
    attrs*: seq[IdlAttr]

  IdlMethod* = object
    name*: string
    returnType*: IdlType
    params*: seq[IdlField]
    opnum*: int           ## inferred from declaration order if not given

  IdlInterface* = object
    name*: string
    attrs*: seq[IdlAttr]      ## interface-level (uuid, version, ...)
    structs*: seq[IdlStruct]
    methods*: seq[IdlMethod]

proc hasAttr*(attrs: openArray[IdlAttr]; k: IdlAttrKind): bool =
  for a in attrs:
    if a.kind == k: return true

proc getAttr*(attrs: openArray[IdlAttr]; k: IdlAttrKind): IdlAttr =
  for a in attrs:
    if a.kind == k: return a
