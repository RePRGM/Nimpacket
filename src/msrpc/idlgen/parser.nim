## idlgen/parser.nim — recursive-descent parser for the IDL subset.
##
## What we recognize:
##   * ``interface Name { ... }`` blocks with ``[uuid(...), version(...)]``
##     attributes preceding them.
##   * ``typedef struct { ... } Name;`` style declarations.
##   * Method declarations inside an interface, of the form
##     ``RetType MethodName([attrs] Type Name, ...);``
##   * Parameter attributes: in, out, unique, ref, ptr, string,
##     context_handle, size_is(name), length_is(name), switch_is(name).
##
## What we deliberately ignore:
##   * Unions (we'd want them; deferred to v2 of the generator).
##   * cpp_quote, import, library declarations (treated as opaque).
##   * Range attributes (parsed but unused in codegen).
##   * Enums with explicit values (rare in protocols we target).

import std/[strutils, strformat]
import lexer, ast

type
  ParseError* = object of CatchableError
  Parser* = ref object
    lx: Lexer
    cur: Token

proc parseError(p: Parser; msg: string) =
  raise newException(ParseError,
    fmt"{p.cur.line}:{p.cur.col}: {msg} (at '{p.cur.text}')")

proc advance(p: Parser) =
  p.cur = p.lx.next()

proc newParser*(src: string): Parser =
  result = Parser(lx: newLexer(src))
  result.advance()

proc expect(p: Parser; k: TokenKind): Token =
  if p.cur.kind != k:
    p.parseError("expected " & $k)
  result = p.cur
  p.advance()

proc accept(p: Parser; k: TokenKind): bool =
  if p.cur.kind == k:
    p.advance(); true
  else: false

proc acceptKeyword(p: Parser; kw: string): bool =
  if p.cur.kind == tkIdent and p.cur.text == kw:
    p.advance(); true
  else: false

# --- attributes -----------------------------------------------------

proc parseSingleAttr(p: Parser): IdlAttr =
  let name = p.expect(tkIdent).text
  case name
  of "in":             result = IdlAttr(kind: aIn)
  of "out":            result = IdlAttr(kind: aOut)
  of "ref":            result = IdlAttr(kind: aRef)
  of "unique":         result = IdlAttr(kind: aUnique)
  of "ptr":            result = IdlAttr(kind: aPtr)
  of "string":         result = IdlAttr(kind: aString)
  of "context_handle": result = IdlAttr(kind: aContextHandle)
  of "v1_enum":        result = IdlAttr(kind: aV1Enum)
  of "local":          result = IdlAttr(kind: aLocal)
  of "object":         result = IdlAttr(kind: aObject)
  of "restricted":     result = IdlAttr(kind: aRestricted)
  of "size_is", "length_is", "first_is", "max_is",
     "switch_is", "switch_type", "range", "uuid", "version",
     "pointer_default", "endpoint", "id", "helpstring", "import":
    let kind = case name
               of "size_is": aSizeIs
               of "length_is": aLengthIs
               of "first_is": aFirstIs
               of "max_is": aMaxIs
               of "switch_is": aSwitchIs
               of "switch_type": aSwitchType
               of "range": aRange
               of "uuid": aUuid
               of "version": aVersion
               of "pointer_default": aPointerDefault
               of "endpoint": aEndpoint
               of "id": aId
               of "helpstring": aHelpString
               of "import": aImport
               else: aIn
    result = IdlAttr(kind: kind)
    discard p.expect(tkLParen)
    while p.cur.kind != tkRParen:
      var s = ""
      # Concatenate raw token text without spaces — UUIDs and version
      # numbers come through as multi-token sequences (dashes / dots
      # being separate tokens) and need to round-trip verbatim.
      while p.cur.kind notin {tkComma, tkRParen, tkEof}:
        s.add p.cur.text
        p.advance()
      result.args.add s.strip()
      if p.cur.kind == tkComma: p.advance()
    discard p.expect(tkRParen)
  else:
    # Unknown attribute — record by name for completeness.
    result = IdlAttr(kind: aIn, args: @[name])

proc parseAttrList(p: Parser): seq[IdlAttr] =
  if not p.accept(tkLBrack): return @[]
  while p.cur.kind != tkRBrack:
    result.add p.parseSingleAttr()
    if p.cur.kind == tkComma: p.advance()
  discard p.expect(tkRBrack)

# --- types ----------------------------------------------------------

const BuiltinTypes = [
  "void", "byte", "boolean", "char", "wchar_t", "short", "long", "hyper",
  "DWORD", "WORD", "ULONG", "USHORT", "BYTE", "BOOLEAN", "BOOL",
  "LONG", "SHORT", "CHAR", "HRESULT", "ACCESS_MASK", "NTSTATUS",
  "LPWSTR", "PWSTR", "LPSTR", "PSTR", "GUID", "UUID",
  "RPC_STRING", "RPC_UNICODE_STRING", "PRPC_SID", "RPC_SID"]

proc parseType(p: Parser): IdlType =
  # Skip optional "unsigned"/"signed" modifiers.
  if p.cur.kind == tkIdent and p.cur.text in ["unsigned", "signed"]:
    p.advance()
    # "unsigned long", "unsigned short", etc.
    if p.cur.kind == tkIdent:
      let combined = p.cur.text
      p.advance()
      result = IdlType(kind: tBuiltin, name: combined)
    else:
      p.parseError("expected base type after unsigned/signed")
  elif p.cur.kind == tkIdent:
    let n = p.cur.text
    p.advance()
    if n in BuiltinTypes:
      result = IdlType(kind: tBuiltin, name: n)
    elif n == "struct":
      # Anonymous nested struct — return a marker; the generator can
      # treat it as opaque. Skip its body.
      if p.cur.kind == tkLBrace:
        var depth = 0
        while p.cur.kind != tkEof:
          if p.cur.kind == tkLBrace: inc depth
          elif p.cur.kind == tkRBrace:
            dec depth
            if depth == 0: p.advance(); break
          p.advance()
      result = IdlType(kind: tNamed, name: "AnonymousStruct")
    else:
      result = IdlType(kind: tNamed, name: n)
  else:
    p.parseError("expected type")
  # Suffix *: pointer levels
  while p.cur.kind == tkStar:
    p.advance()
    result = IdlType(kind: tPointer, target: result)

# --- fields / params ------------------------------------------------

proc parseField(p: Parser): IdlField =
  result.attrs = p.parseAttrList()
  result.typ = p.parseType()
  result.name = p.expect(tkIdent).text
  # Optional C-style array suffix: name[Size]
  if p.accept(tkLBrack):
    if p.cur.kind == tkRBrack:
      # ``T name[]`` — open array (conformant)
      discard
    else:
      let n = p.expect(tkNumber).text
      try:
        result.typ = IdlType(kind: tArray, element: result.typ,
                              size: parseInt(n))
      except ValueError:
        p.parseError("invalid array size")
    discard p.expect(tkRBrack)

proc parseStructBody(p: Parser): seq[IdlField] =
  discard p.expect(tkLBrace)
  while p.cur.kind != tkRBrace:
    let f = p.parseField()
    result.add f
    discard p.expect(tkSemi)
  discard p.expect(tkRBrace)

# --- declarations ---------------------------------------------------

proc parseTypedef(p: Parser; attrs: seq[IdlAttr]): IdlStruct =
  # ``typedef`` already consumed by caller. Accept additional inline
  # attribute lists between ``typedef`` and the type (e.g.
  # ``typedef [context_handle] PVOID HANDLE;``).
  var allAttrs = attrs
  if p.cur.kind == tkLBrack:
    allAttrs.add p.parseAttrList()
  if p.cur.kind == tkIdent and p.cur.text == "struct":
    p.advance()
    # optional struct tag name (ignored)
    if p.cur.kind == tkIdent and p.cur.text != "{":
      p.advance()
    result.fields = p.parseStructBody()
    # final name
    result.name = p.expect(tkIdent).text
    # optional pointer typedef synonyms: ``, *PFoo`` — skip
    while p.cur.kind == tkComma:
      p.advance()
      while p.cur.kind == tkStar: p.advance()
      if p.cur.kind == tkIdent: p.advance()
    result.attrs = allAttrs
    discard p.expect(tkSemi)
  else:
    # Other typedef forms (typedef T Alias;) — produce an empty struct
    # so the generator at least sees the name.
    let baseTy = p.parseType()
    discard baseTy
    let aliasName = p.expect(tkIdent).text
    result.name = aliasName
    result.attrs = allAttrs
    while p.cur.kind == tkComma:
      p.advance()
      while p.cur.kind == tkStar: p.advance()
      if p.cur.kind == tkIdent: p.advance()
    discard p.expect(tkSemi)

proc parseMethod(p: Parser): IdlMethod =
  # Already consumed the leading attribute list (passed in via parseInterface)
  result.returnType = p.parseType()
  result.name = p.expect(tkIdent).text
  discard p.expect(tkLParen)
  while p.cur.kind != tkRParen:
    let f = p.parseField()
    result.params.add f
    if p.cur.kind == tkComma: p.advance()
  discard p.expect(tkRParen)
  discard p.expect(tkSemi)

proc parseInterface(p: Parser; attrs: seq[IdlAttr]): IdlInterface =
  result.attrs = attrs
  # 'interface' keyword consumed
  result.name = p.expect(tkIdent).text
  # optional ': BaseName'
  if p.accept(tkColon):
    discard p.expect(tkIdent)
  discard p.expect(tkLBrace)
  var opnum = 0
  while p.cur.kind != tkRBrace:
    # Each declaration may have leading attributes.
    let memberAttrs = p.parseAttrList()
    if p.acceptKeyword("typedef"):
      let s = p.parseTypedef(memberAttrs)
      result.structs.add s
    else:
      var m = p.parseMethod()
      m.opnum = opnum
      m.params.insert(IdlField(attrs: memberAttrs), 0)
      m.params.delete(0)         # the captured attrs apply to the method, not a param
      result.methods.add m
      inc opnum
  discard p.expect(tkRBrace)
  discard p.accept(tkSemi)

proc parseIdl*(p: Parser): seq[IdlInterface] =
  while p.cur.kind != tkEof:
    if p.acceptKeyword("import"):
      # import "foo.idl"; — skip
      while p.cur.kind != tkSemi and p.cur.kind != tkEof: p.advance()
      discard p.accept(tkSemi)
      continue
    if p.acceptKeyword("cpp_quote"):
      discard p.expect(tkLParen)
      discard p.expect(tkString)
      discard p.expect(tkRParen)
      discard p.accept(tkSemi)
      continue
    let attrs = p.parseAttrList()
    if p.acceptKeyword("interface"):
      result.add p.parseInterface(attrs)
    elif p.acceptKeyword("typedef"):
      # Top-level typedef. We need a container interface to attach it
      # to — synthesize an anonymous one if none exists yet.
      if result.len == 0:
        result.add IdlInterface(name: "_TopLevel")
      result[^1].structs.add p.parseTypedef(attrs)
    elif p.cur.kind == tkEof:
      break
    else:
      # Unknown top-level decl — skip until next ';' to be tolerant.
      while p.cur.kind notin {tkSemi, tkEof}: p.advance()
      discard p.accept(tkSemi)
