## ldap/messages.nim — LDAP protocol-op encoders and parsers (RFC 4511).
##
##   LDAPMessage ::= SEQUENCE {
##       messageID  INTEGER,
##       protocolOp CHOICE {
##           bindRequest    [APPLICATION 0] BindRequest,
##           bindResponse   [APPLICATION 1] BindResponse,
##           unbindRequest  [APPLICATION 2] UnbindRequest,
##           searchRequest  [APPLICATION 3] SearchRequest,
##           searchResEntry [APPLICATION 4] SearchResultEntry,
##           searchResDone  [APPLICATION 5] SearchResultDone, ... } }

import ../common/buffers
import ber

type
  LdapResultCode* = enum
    rcSuccess                = 0
    rcOperationsError        = 1
    rcProtocolError          = 2
    rcTimeLimitExceeded      = 3
    rcSizeLimitExceeded      = 4
    rcCompareFalse           = 5
    rcCompareTrue            = 6
    rcAuthMethodNotSupported = 7
    rcStrongerAuthRequired   = 8
    rcReferral               = 10
    rcSaslBindInProgress     = 14
    rcNoSuchAttribute        = 16
    rcNoSuchObject           = 32
    rcInvalidDNSyntax        = 34
    rcInvalidCredentials     = 49
    rcInsufficientAccessRights = 50
    rcBusy                   = 51
    rcUnavailable            = 52
    rcUnwillingToPerform     = 53
    rcOther                  = 80

  LdapScope* = enum
    lsBaseObject  = 0
    lsSingleLevel = 1
    lsWholeSubtree = 2

  LdapDerefAlias* = enum
    daNeverDerefAliases       = 0
    daDerefInSearching        = 1
    daDerefFindingBaseObj     = 2
    daDerefAlways             = 3

  AttributeValue* = object
    name*: string
    values*: seq[seq[byte]]

  SearchResultEntry* = object
    dn*: string
    attributes*: seq[AttributeValue]

  SearchResultDone* = object
    resultCode*: int
    matchedDN*: string
    diagnosticMessage*: string

# --- BindRequest helpers (simple auth) -----------------------------

proc buildBindRequest*(messageId: int; bindDn, password: string;
                       version: int = 3): seq[byte] =
  let inner = newBuffer()
  inner.writeBytes(berEncodeInt(int64(version)))
  inner.writeBytes(derTLV(tagOctetString, cast[seq[byte]](bindDn)))
  inner.writeBytes(derTLV(ctxPrimitive(0), cast[seq[byte]](password)))
  let bindReq = derTLV(appConstructed(0), inner.consumed)
  let msg = newBuffer()
  msg.writeBytes(berEncodeInt(int64(messageId)))
  msg.writeBytes(bindReq)
  result = derTLV(tagSequence, msg.consumed)

proc buildUnbindRequest*(messageId: int): seq[byte] =
  let inner = newBuffer()
  inner.writeBytes(berEncodeInt(int64(messageId)))
  inner.writeBytes(@[appPrimitive(2), 0'u8])
  result = derTLV(tagSequence, inner.consumed)

# --- Filters -------------------------------------------------------

proc buildPresenceFilter*(attrName: string): seq[byte] =
  derTLV(ctxPrimitive(7), cast[seq[byte]](attrName))

proc buildEqualityFilter*(attrName: string; value: openArray[byte]): seq[byte] =
  let inner = newBuffer()
  inner.writeBytes(derTLV(tagOctetString, cast[seq[byte]](attrName)))
  inner.writeBytes(derTLV(tagOctetString, value))
  result = derTLV(ctxConstructed(3), inner.consumed)

proc buildAndFilter*(parts: openArray[seq[byte]]): seq[byte] =
  let inner = newBuffer()
  for p in parts: inner.writeBytes(p)
  result = derTLV(ctxConstructed(0), inner.consumed)

# --- SearchRequest -------------------------------------------------

proc buildSearchRequest*(messageId: int; baseDn: string; scope: LdapScope;
                         deref: LdapDerefAlias = daNeverDerefAliases;
                         sizeLimit: int = 0; timeLimit: int = 0;
                         typesOnly: bool = false;
                         filter: openArray[byte];
                         attributes: openArray[string]): seq[byte] =
  let inner = newBuffer()
  inner.writeBytes(derTLV(tagOctetString, cast[seq[byte]](baseDn)))
  inner.writeBytes(berEnumerated(ord(scope)))
  inner.writeBytes(berEnumerated(ord(deref)))
  inner.writeBytes(berEncodeInt(int64(sizeLimit)))
  inner.writeBytes(berEncodeInt(int64(timeLimit)))
  inner.writeBytes(berEncodeBool(typesOnly))
  inner.writeBytes(@filter)
  let attrList = newBuffer()
  for a in attributes:
    attrList.writeBytes(derTLV(tagOctetString, cast[seq[byte]](a)))
  inner.writeBytes(derTLV(tagSequence, attrList.consumed))

  let searchReq = derTLV(appConstructed(3), inner.consumed)
  let msg = newBuffer()
  msg.writeBytes(berEncodeInt(int64(messageId)))
  msg.writeBytes(searchReq)
  result = derTLV(tagSequence, msg.consumed)

# --- Response parsing ---------------------------------------------

type
  LdapOpKind* = enum
    lokBindResponse
    lokSearchResultEntry
    lokSearchResultDone
    lokOther

  LdapMessage* = object
    messageId*: int
    case kind*: LdapOpKind
    of lokBindResponse, lokSearchResultDone:
      doneResult*: SearchResultDone
    of lokSearchResultEntry:
      entry*: SearchResultEntry
    of lokOther:
      opTag*: byte
      opBody*: seq[byte]

proc parseLdapResultPart(b: Buffer; endPos: int): SearchResultDone =
  let codeLen = b.derReadTag(tagEnumerated)
  var code = 0
  for _ in 0 ..< codeLen:
    code = (code shl 8) or int(b.readByte())
  result.resultCode = code
  let matchedLen = b.derReadTag(tagOctetString)
  result.matchedDN = ""
  for _ in 0 ..< matchedLen: result.matchedDN.add char(b.readByte())
  let diagLen = b.derReadTag(tagOctetString)
  result.diagnosticMessage = ""
  for _ in 0 ..< diagLen: result.diagnosticMessage.add char(b.readByte())
  if b.pos < endPos: b.seek(endPos)

proc parseSearchResultEntryBody(b: Buffer; endPos: int): SearchResultEntry =
  let dnLen = b.derReadTag(tagOctetString)
  result.dn = ""
  for _ in 0 ..< dnLen: result.dn.add char(b.readByte())
  let attrsLen = b.derReadTag(tagSequence)
  let attrsEnd = b.pos + attrsLen
  while b.pos < attrsEnd:
    let pLen = b.derReadTag(tagSequence)
    let pEnd = b.pos + pLen
    let nameLen = b.derReadTag(tagOctetString)
    var name = ""
    for _ in 0 ..< nameLen: name.add char(b.readByte())
    var av: AttributeValue
    av.name = name
    let setLen = b.derReadTag(tagSet)
    let setEnd = b.pos + setLen
    while b.pos < setEnd:
      let vLen = b.derReadTag(tagOctetString)
      av.values.add b.readBytes(vLen)
    b.seek(pEnd)
    result.attributes.add av
  b.seek(endPos)

proc parseLdapMessage*(data: openArray[byte]): LdapMessage =
  let b = newBuffer(@data)
  let outerLen = b.derReadTag(tagSequence)
  let outerEnd = b.pos + outerLen
  let mid = int(berParseInt(b))
  let opTag = b.readByte()
  let opLen = b.derReadLen()
  let opEnd = b.pos + opLen
  case opTag
  of appConstructed(1):
    result = LdapMessage(kind: lokBindResponse, messageId: mid,
                         doneResult: parseLdapResultPart(b, opEnd))
  of appConstructed(4):
    result = LdapMessage(kind: lokSearchResultEntry,
                          messageId: mid,
                          entry: parseSearchResultEntryBody(b, opEnd))
  of appConstructed(5):
    result = LdapMessage(kind: lokSearchResultDone,
                          messageId: mid,
                          doneResult: parseLdapResultPart(b, opEnd))
  else:
    let body = b.readBytes(opLen)
    result = LdapMessage(kind: lokOther, messageId: mid,
                          opTag: opTag, opBody: body)
  if b.pos < outerEnd: b.seek(outerEnd)

# --- pretty-print -------------------------------------------------

proc valueAsString*(v: openArray[byte]): string =
  result = ""
  for b in v:
    if b >= 0x20'u8 and b < 0x7f'u8: result.add char(b)
    else: result.add '.'

{.push warning[HoleEnumConv]: off.}
proc resultName*(code: int): string =
  try: $LdapResultCode(code)
  except CatchableError: "code(" & $code & ")"
{.pop.}
