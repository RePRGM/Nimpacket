import std/[macros, tables, strutils, endians, strformat, sequtils]
#import unicode

from ../utils/utils import toUtf16LE

type  
  absSyntaxID* = object
    ifUUID*: array[16, uint8]
    ifVersion*: uint16
    ifMinorVersion*: uint16

  presContextElement* = object
    contextID*: uint16
    numTransSyntaxes*: uint8
    padding*: uint8
    absSyntax*: absSyntaxID
    transSyntax*: absSyntaxID

  PDUHeader* = object
    version*: uint8
    minorVersion*: uint8
    pType*: uint8
    pFlags*: uint8
    dRep*: array[4, uint8]
    
    fragLength*: uint16
    authLength*: uint16
    callID*: uint32

  PDUBind* = object
    header*: PDUHeader
    maxXmitFrag*: uint16
    maxRecvFrag*: uint16
    assocGroupID*: uint32
    numContextElements*: uint8

  PDURequest* = object
    header*: PDUHeader
    allocHint*: uint32
    contextID*: uint16
    opNum*: uint16

# Claude Testing NDR Encoding

  NDRContext* = object
    data*: seq[uint8]
    position*: int
    nextRefId*: uint32
    pointerMap*: Table[pointer, uint32]

  NDRKind* = enum
    nkPrimitive
    nkConformant
    nkPointer
    nkStruct
    nkUnion
    nkString

  NDRMeta = object
    kind*: NDRKind
    isUnique*: bool
    isConformant*: bool
    isVarying*: bool
    alignment*: int

  SHARE_INFO_1* {.packed.} = object
    shi1_netname*: string
    shi1_type*: uint32
    shi1_remark*: string

  SHARE_INFO_1_CONTAINER* {.packed.} = object
    EntriesRead*: uint32
    Buffer*: ptr SHARE_INFO_1
  
  ShareEnumLevel* = enum
    Level0 = 0
    Level1 = 1
    Level2 = 2
    Level501 = 501
    Level502 = 502
    Level503 = 503

  ShareEnumUnion* {.packed.} = object
    case level*: ShareEnumLevel
    of Level0:
      level0*: pointer
    of Level1:
      level1*: ptr SHARE_INFO_1_CONTAINER
    of Level2:
      level2*: pointer
    of Level501:
      level501*: pointer
    of Level502:
      level502*: pointer
    of Level503:
      level503*: pointer

# Forward declarations
proc getNDRMeta*[T](t: typedesc[T]): NDRMeta
proc encode*[T](ctx: var NDRContext, value: T)
proc encodePointer*[T](ctx: var NDRContext, value: ptr T)
proc encodeStruct*[T: object](ctx: var NDRContext, value: T)
#proc encodeUnion*[T, P](ctx: var NDRContext, value: T, parentValue: P)
proc encodeInt32*(ctx: var NDRContext, value: int32)
proc encodeInt64Aligned*(ctx: var NDRContext, value: int32)


macro hasPrimitiveFields(T: typedesc): bool =
  let impl = getTypeImpl(getType(T)[1])  # Get actual type implementation
  var hasUint32 = false
  for field in impl[2]:
    if field.kind == nnkIdentDefs:
      let fieldType = field[1]
      if fieldType.eqIdent("uint32") or fieldType.eqIdent("int32") or fieldType.eqIdent("int"):
        hasUint32 = true
        break
  result = newLit(hasUint32)
  
macro isTaggedUnion(T: typedesc): bool =
  var impl = T.getTypeImpl  # First get typeDesc
  if impl.kind == nnkBracketExpr:
    impl = getTypeImpl(impl[1])  # Get actual type implementation
    if impl.kind == nnkObjectTy:
      for field in impl[2]:
        if field.kind == nnkRecCase:
          return newLit(true)
  return newLit(false)

# Add the generic encode proc first
proc encode*[T](ctx: var NDRContext, value: T) =
  when T is ptr:
    echo "encode called with ptr type: ", T
    encodePointer(ctx, value)
  elif T is pointer:
    echo "encode called with pointer (null) type: ", T
    encodeInt64Aligned(ctx, 0)  # Encode null for raw pointers
  elif T is object:
    echo "encode called with object type: ", T
    encodeStruct(ctx, value)
  elif T is uint32:
    echo "encode called with uint32 type: ", T
    encodeUint32(ctx, value)
  elif T is int32:
    echo "encode called with int32 type: ", T
    encodeInt32(ctx, value)
  elif T.getTypeImpl.kind == nnkEnumTy:
    echo "T is an enum"
    echo "value: ", value.ord.uint32
    encodeUint32(ctx, value.ord.uint32)

# Then implement the other procedures
proc encodePointer[T](ctx: var NDRContext, value: ptr T) =
  echo "encodePointer called with type: ptr ", T.repr
  if value.isNil:
    echo "value is nil"
    encodeInt64Aligned(ctx, 0)
    return

  when T is object:
    echo "Inside encodePointer. T.repr: ", T.repr
    echo "isTaggedUnion(T): ", isTaggedUnion(T)
    # Terrible way to handle special rules for tagged unions
    if isTaggedUnion(T):
    #if hasPrimitiveFields(T) or isTaggedUnion(T):
      #echo "hasPrimitiveFields: TRUE"
      # For structs with primitive fields (like uint32),
      # encode contents first (which includes the "referent ID-like" value)
      encode(ctx, value[])
    else:
      #echo "hasPrimitiveFields: FALSE"
      # For embedded pointer structs, add real referent ID first
      encodeInt64Aligned(ctx, ctx.nextRefId.int32)
      echo "ctx.nextRefId: ", ctx.nextRefId
      inc ctx.nextRefId
      encode(ctx, value[])
  elif T is SomeInteger:
    echo "T is SomeInteger"
    encodeUint32(ctx, value[].uint32)

# Macro for getting union structure
#macro getUnionFields(T: typedesc): seq[tuple[name: string, typ: NimNode]] =
#  result = newSeq[NimNode]()
#  let typeImpl = getTypeImpl(T)
#  
#  if typeImpl.kind == nnkBracketExpr and typeImpl[0].kind == nnkSym:
#    let realType = getTypeImpl(typeImpl[0])
#    for field in realType[2]:
#      if field.kind == nnkRecCase:
#        for branch in field[1..^1]:
#          if branch.kind == nnkOfBranch:
#            result.add((branch[1][0].strVal, branch[1][1]))

macro isUnionType*(T: typedesc): bool =
  let impl = getTypeImpl(T)  # Try direct type implementation first
  if impl.kind == nnkBracketExpr and impl[1].kind == nnkSym:
    let sym = impl[1]
    let symImpl = sym.getImpl
    if symImpl.kind == nnkTypeDef and 
       symImpl[0].kind == nnkPragmaExpr and
       symImpl[0][1].kind == nnkPragma and
       symImpl[0][1][0].kind == nnkIdent and
       symImpl[0][1][0].strVal == "union":
      return newLit(true)
  result = newLit(false)

proc write(ctx: var NDRContext, bytes: openArray[uint8]) =
  ctx.data.add(bytes)
  ctx.position += bytes.len

proc alignStream(ctx: var NDRContext, alignment: int) =
  let padding = (alignment - (ctx.position mod alignment)) mod alignment
  for i in 0..<padding:
    ctx.write([0'u8])

#macro getUnionBranches(T: typedesc): untyped =
#  # Get type implementation
#  let impl = getTypeImpl(getType(T)[1])
#  echo "Type impl: ", treeRepr(impl)
#  
#  # Create tuple to hold discriminator and branches
#  result = newTree(nnkTupleConstr)
#  
#  if impl.kind == nnkObjectTy:
#    for field in impl[2]:
#      if field.kind == nnkRecCase:
#        # Store discriminator field
#        result.add(field[0])
#        
#        # Create array for branches
#        var branches = newTree(nnkBracket)
#        
#        # Process each branch
#        for branch in field[1..^1]:
#          if branch.kind == nnkOfBranch:
#            let values = branch[0..^2]  # All but last node are values
#            let fieldName = branch[^1][0]  # Field name
#            
#            # Add tuple of (value, fieldname) for each value
#            for val in values:
#              branches.add(newTree(nnkTupleConstr, val, fieldName))
#        
#        result.add(branches)
#  
#  echo "Result: ", treeRepr(result)
#
#discard getUnionBranches(SHARE_ENUM_UNION)

# WORKS
#macro encodeUnion[T](ctx: var NDRContext, value: T): untyped =
#  echo "encodeUnion called with type: ", value.getType.repr
#  # Get union type impl
#  var typeImpl = getTypeImpl(T)
#  if typeImpl.kind == nnkBracketExpr:
#    typeImpl = getTypeImpl(typeImpl[1])
#  
#  if typeImpl.kind == nnkObjectTy:
#    let firstField = typeImpl[2][0]  # First field from RecList
#    let fieldName = firstField[0]    # Field identifier
#    
#    result = quote do:
#      encodePointer(`ctx`, `value`.`fieldName`)

#macro encodeUnion[T](ctx: var NDRContext, value: T, discriminator: typed): untyped =
#  # Get type implementation
#  var typeImpl = getTypeImpl(T)
#  if typeImpl.kind == nnkBracketExpr:
#    typeImpl = getTypeImpl(typeImpl[1])
#  
#  if typeImpl.kind == nnkObjectTy:
#    let fields = typeImpl[2]  # RecList
#    
#    # Create case statement for field selection
#    var caseStmt = nnkCaseStmt.newTree(discriminator)
#    
#    # Add branch for each field
#    for i, field in fields.pairs:
#      if field.kind == nnkIdentDefs:
#        let fieldName = field[0]
#        let branch = nnkOfBranch.newTree(
#          newIntLitNode(i),
#          quote do:
#            encode(`ctx`, `value`.`fieldName`)
#        )
#        caseStmt.add(branch)
#    
#    # Add else branch
#    caseStmt.add(
#      nnkElse.newTree(
#        quote do:
#          raise newException(ValueError, "Invalid discriminator value")
#      )
#    )
#    
#    result = caseStmt
macro getDiscriminant(value: typed): untyped =
  # For variant objects, get the case discriminator field and value
  let impl = getTypeImpl(value)
  for field in impl[2]:
    if field.kind == nnkRecCase:
      let discField = field[0][0]  # Get discriminator field name
      return quote do:
        `value`.`discField`

macro getUnionValue(value: typed, disc: typed): untyped =
  let impl = getTypeImpl(value)
  result = newEmptyNode()
  for field in impl[2]:
    if field.kind == nnkRecCase:
      for branch in field[1..^1]:
        if branch.kind == nnkOfBranch:
          let val = branch[0]
          # Just get field identifier
          let fieldName = branch[^1][0].strVal
          let fieldIdent = ident(fieldName)
          result = quote do:
            if `disc` == `val`:
              `value`.`fieldIdent`

#proc encodeUnion(ctx: var NDRContext, value: object) =
#  # Get the discriminator field and value via case field
#  let discriminator = getDiscriminant(value)
#  let activeField = getUnionValue(value, discriminator)
#  encode(ctx, activeField)

# NDR metadata for our types
proc getNDRMeta*[T](t: typedesc[T]): NDRMeta =
  # Base implementation
  when T is int32 or T is uint32:
    result = NDRMeta(kind: nkPrimitive, alignment: 4)
  elif T is string:
    result = NDRMeta(kind: nkString, isUnique: true, alignment: 8)
  elif T is pointer or T is ptr:
    result = NDRMeta(kind: nkPointer, isUnique: true, alignment: 8)
  elif T is object:
    when T.isUnionType:
      result = NDRMeta(kind: nkUnion, alignment: 8)
    else:
      result = NDRMeta(kind: nkStruct, alignment: 8)
  else:
    raise newException(ValueError, "Unsupported type for NDR encoding")

proc getNDRMeta*(T: typedesc[int32]): NDRMeta =
  NDRMeta(kind: nkPrimitive, alignment: 4)

proc getNDRMeta*(T: typedesc[uint32]): NDRMeta =
  NDRMeta(kind: nkPrimitive, alignment: 4)

proc getNDRMeta*(T: typedesc[string]): NDRMeta =
  NDRMeta(kind: nkString, isUnique: true, alignment: 8)

proc getNDRMeta*[T](t: typedesc[ptr T]): NDRMeta =
  NDRMeta(kind: nkPointer, isUnique: true, alignment: 8)

proc getNDRMeta*[T](t: typedesc[pointer]): NDRMeta =
  NDRMeta(kind: nkPointer, isUnique: true, alignment: 8)

proc getNDRMeta*(T: typedesc[SHARE_INFO_1]): NDRMeta =
  NDRMeta(kind: nkStruct, alignment: 8)

proc getNDRMeta*(T: typedesc[SHARE_INFO_1_CONTAINER]): NDRMeta =
  NDRMeta(kind: nkStruct, alignment: 8)

proc encodeInt32*(ctx: var NDRContext, value: int32) =
  var bytes: array[4, uint8]
  littleEndian32(addr bytes[0], unsafeAddr value)
  ctx.write(bytes)

proc encodeInt64Aligned*(ctx: var NDRContext, value: int32) =
  alignStream(ctx, 8)
  encodeInt32(ctx, value)
  ctx.write([0'u8, 0'u8, 0'u8, 0'u8])  # Add exactly 4 bytes padding

proc encodeUint32*(ctx: var NDRContext, value: uint32) =
  var bytes: array[4, uint8]
  littleEndian32(addr bytes[0], unsafeAddr value)
  ctx.write(bytes)
  alignStream(ctx, 8)

proc encodeString*(ctx: var NDRContext, value: string, isUnique: bool = false) =
  if isUnique:
    # Encode unique pointer referent ID
    echo "Encoding unique pointer referent ID"
    encodeInt64Aligned(ctx, 0x20000'i32)
    #encodeInt64Aligned(ctx, ctx.nextRefId.int32)
    #inc ctx.nextRefId
  
  let utf16Str = toUtf16LE(value & "\0")
  let maxCount = utf16Str.len div 2
  
  # Encode counts consecutively without padding
  encodeUint32(ctx, maxCount.uint32)  # maxCount
  encodeUint32(ctx, 0'u32)            # offset
  encodeUint32(ctx, maxCount.uint32)  # actual count
  
  # Write the actual string data
  if maxCount > 0:
    ctx.write(utf16Str)

proc encodeStruct*[T: object](ctx: var NDRContext, value: T) =
    for field in fields(value):
      echo "Inside encodeStruct. Field: ", field.repr
      encode(ctx, field)
#  if T.isUnionType:
#    echo "T is a union type"
#    # If the struct itself is a union
#    encodeUnion(ctx, value)
#  else:
#    for field in fields(value):
#      echo "Inside encodeStruct. Field: ", field.repr
#      if field.type.isUnionType:
#        echo "Field is a union type"
#        # For embedded unions, add referent ID first
#        encodeInt64Aligned(ctx, ctx.nextRefId.int32+1)
#        inc ctx.nextRefId
#        encodeUnion(ctx, field)
#      else:
#        encode(ctx, field)

# Test function
proc NetrShareEnum*(ServerName: string, InfoStruct: ptr ShareEnumUnion, PreferedMaximumLength: uint32 = cast[uint32](-1), TotalEntries: ptr uint32 = nil, ResumeHandle: ptr uint32 = nil): seq[uint8] =
  var ctx = NDRContext(data: @[], position: 0, nextRefId: 1, pointerMap: initTable[pointer, uint32]())
  
  # Encode ServerName as unique string
  encodeString(ctx, ServerName, true)
  
  # Encode InfoStruct pointer and its contents
  encodePointer(ctx, InfoStruct)
  
  # Encode remaining parameters
  encodePointer(ctx, TotalEntries) # WireShark seems to show this parameter prior to prefMaxLength, although MSDN says the opposite
  encodeUint32(ctx, PreferedMaximumLength)
  encodePointer(ctx, ResumeHandle)
  
  result = ctx.data
