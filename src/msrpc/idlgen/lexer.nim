## idlgen/lexer.nim — minimal MIDL tokenizer.
##
## We don't try to be a full MIDL parser — just enough to digest the
## kind of fragments Microsoft Open Specifications use to define a
## protocol's data types and opnum signatures.

import std/strutils

type
  TokenKind* = enum
    tkIdent, tkNumber, tkString,
    tkLBrace, tkRBrace, tkLParen, tkRParen, tkLBrack, tkRBrack,
    tkComma, tkSemi, tkStar, tkEq, tkColon,
    tkEof, tkUnknown

  Token* = object
    kind*: TokenKind
    text*: string
    line*: int
    col*: int

  Lexer* = object
    src*: string
    pos*: int
    line*: int
    col*: int

const Keywords* = [
  "void", "byte", "boolean", "char", "wchar_t",
  "short", "long", "hyper",
  "unsigned", "signed",
  "struct", "union", "enum", "switch", "case", "default",
  "typedef", "interface", "library", "import", "cpp_quote",
  "in", "out", "ptr", "ref", "unique", "string", "context_handle",
  "size_is", "length_is", "first_is", "max_is", "switch_is", "switch_type",
  "range", "v1_enum", "handle_t",
  "uuid", "version", "pointer_default", "endpoint", "object",
  "id", "helpstring", "local", "restricted",
  # Common Windows types
  "DWORD", "WORD", "ULONG", "USHORT", "BYTE", "BOOLEAN",
  "LPWSTR", "PWSTR", "LPSTR", "PSTR", "GUID", "UUID",
  "RPC_STRING", "RPC_UNICODE_STRING", "NTSTATUS",
  "PRPC_SID", "RPC_SID", "ACCESS_MASK",
  "HRESULT", "BOOL", "LONG", "SHORT", "CHAR"]

proc isIdentStart(c: char): bool = c.isAlphaAscii or c == '_'
proc isIdentCont(c: char): bool = c.isAlphaNumeric or c == '_'

proc newLexer*(src: string): Lexer =
  Lexer(src: src, pos: 0, line: 1, col: 1)

proc skipWhitespaceAndComments(lx: var Lexer) =
  while lx.pos < lx.src.len:
    let c = lx.src[lx.pos]
    if c in {' ', '\t', '\r'}:
      inc lx.pos; inc lx.col
    elif c == '\n':
      inc lx.pos; inc lx.line; lx.col = 1
    elif c == '/' and lx.pos + 1 < lx.src.len and lx.src[lx.pos + 1] == '/':
      while lx.pos < lx.src.len and lx.src[lx.pos] != '\n': inc lx.pos
    elif c == '/' and lx.pos + 1 < lx.src.len and lx.src[lx.pos + 1] == '*':
      lx.pos += 2; lx.col += 2
      while lx.pos + 1 < lx.src.len and
            not (lx.src[lx.pos] == '*' and lx.src[lx.pos+1] == '/'):
        if lx.src[lx.pos] == '\n': inc lx.line; lx.col = 1
        else: inc lx.col
        inc lx.pos
      if lx.pos + 1 < lx.src.len: lx.pos += 2; lx.col += 2
    elif c == '[' and lx.pos + 1 < lx.src.len and lx.src[lx.pos+1] == '#':
      # Skip MIDL attributes that we don't understand. Actually no — we
      # consume normal [...] attributes via the parser. This branch is
      # just for [#pragma]-style blocks (rare).
      break
    else:
      break

template oneChar(k: TokenKind; ch: string): Token =
  Token(kind: k, text: ch, line: startLine, col: startCol)

proc next*(lx: var Lexer): Token =
  lx.skipWhitespaceAndComments()
  if lx.pos >= lx.src.len:
    return Token(kind: tkEof, line: lx.line, col: lx.col)
  let startLine = lx.line
  let startCol = lx.col
  let c = lx.src[lx.pos]
  case c
  of '{':
    inc lx.pos; inc lx.col; return oneChar(tkLBrace, "{")
  of '}':
    inc lx.pos; inc lx.col; return oneChar(tkRBrace, "}")
  of '(':
    inc lx.pos; inc lx.col; return oneChar(tkLParen, "(")
  of ')':
    inc lx.pos; inc lx.col; return oneChar(tkRParen, ")")
  of '[':
    inc lx.pos; inc lx.col; return oneChar(tkLBrack, "[")
  of ']':
    inc lx.pos; inc lx.col; return oneChar(tkRBrack, "]")
  of ',':
    inc lx.pos; inc lx.col; return oneChar(tkComma, ",")
  of ';':
    inc lx.pos; inc lx.col; return oneChar(tkSemi, ";")
  of '*':
    inc lx.pos; inc lx.col; return oneChar(tkStar, "*")
  of '=':
    inc lx.pos; inc lx.col; return oneChar(tkEq, "=")
  of ':':
    inc lx.pos; inc lx.col; return oneChar(tkColon, ":")
  of '"':
    inc lx.pos; inc lx.col
    var s = ""
    while lx.pos < lx.src.len and lx.src[lx.pos] != '"':
      s.add lx.src[lx.pos]
      inc lx.pos; inc lx.col
    if lx.pos < lx.src.len: inc lx.pos; inc lx.col
    return Token(kind: tkString, text: s, line: startLine, col: startCol)
  of '-', '.':
    # Standalone "-" and "." tokens — used inside attribute args for
    # UUIDs (3aa3-...) and version numbers (1.0). We surface them as
    # tkUnknown so the attribute-arg accumulator can concatenate them.
    let ch = $c
    inc lx.pos; inc lx.col
    return Token(kind: tkUnknown, text: ch, line: startLine, col: startCol)
  else:
    if isIdentStart(c):
      var s = ""
      while lx.pos < lx.src.len and isIdentCont(lx.src[lx.pos]):
        s.add lx.src[lx.pos]
        inc lx.pos; inc lx.col
      return Token(kind: tkIdent, text: s, line: startLine, col: startCol)
    elif c.isDigit:
      var s = ""
      while lx.pos < lx.src.len and
            (lx.src[lx.pos].isDigit or lx.src[lx.pos] in {'x', 'X', '_'} or
             lx.src[lx.pos] in HexDigits):
        s.add lx.src[lx.pos]
        inc lx.pos; inc lx.col
      return Token(kind: tkNumber, text: s, line: startLine, col: startCol)
    else:
      inc lx.pos; inc lx.col
      return Token(kind: tkUnknown, text: $c, line: startLine, col: startCol)

proc peek*(lx: var Lexer): Token =
  let save = lx
  result = lx.next()
  lx = save

proc tokenize*(src: string): seq[Token] =
  var lx = newLexer(src)
  while true:
    let t = lx.next()
    result.add t
    if t.kind == tkEof: break
