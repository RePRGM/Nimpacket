## ldap/client.nim — TCP LDAP client.
##
## Each PDU on the wire is a self-delimited BER SEQUENCE, so we peek
## the outer SEQUENCE header to learn its length and then read exactly
## that many bytes.

import std/net
import messages

type
  LdapError* = object of CatchableError

  LdapClient* = ref object
    sock*: Socket
    nextId*: int

proc newLdapClient*(host: string; port: int = 389): LdapClient =
  result = LdapClient(sock: newSocket(buffered = false), nextId: 1)
  result.sock.connect(host, Port(port))

proc nextMsgId*(c: LdapClient): int =
  result = c.nextId; inc c.nextId

proc send*(c: LdapClient; pdu: openArray[byte]) =
  var s = newString(pdu.len)
  for i, b in pdu: s[i] = char(b)
  c.sock.send(s)

proc recvOne*(c: LdapClient): seq[byte] =
  var head = newString(2)
  if c.sock.recv(head, 2) != 2:
    raise newException(LdapError, "short read on LDAP header")
  doAssert head[0] == char(0x30), "not a SEQUENCE"
  let lenByte = byte(head[1].ord)
  var totalLen = 0
  var headerExtra = 0
  if (lenByte and 0x80) == 0:
    totalLen = int(lenByte)
  else:
    headerExtra = int(lenByte and 0x7F)
    var extra = newString(headerExtra)
    if c.sock.recv(extra, headerExtra) != headerExtra:
      raise newException(LdapError, "short read on LDAP length")
    for ch in extra:
      totalLen = (totalLen shl 8) or int(byte(ch.ord))
    head.add extra
  var body = newString(totalLen)
  var got = 0
  while got < totalLen:
    var chunk = newString(totalLen - got)
    let n = c.sock.recv(chunk, totalLen - got)
    if n <= 0: raise newException(LdapError, "short read on LDAP body")
    for i in 0 ..< n: body[got + i] = chunk[i]
    got += n
  result = newSeq[byte](head.len + body.len)
  for i in 0 ..< head.len: result[i] = byte(head[i].ord)
  for i in 0 ..< body.len: result[head.len + i] = byte(body[i].ord)

proc close*(c: LdapClient) =
  try: c.sock.close()
  except CatchableError: discard

# --- high-level operations ----------------------------------------

proc bindSimple*(c: LdapClient; bindDn, password: string): SearchResultDone =
  ## Simple (DN + password) BindRequest. Empty DN+password = anonymous.
  let id = c.nextMsgId()
  c.send(buildBindRequest(id, bindDn, password))
  let msg = parseLdapMessage(c.recvOne())
  if msg.kind != lokBindResponse:
    raise newException(LdapError, "expected BindResponse")
  result = msg.doneResult

proc search*(c: LdapClient; baseDn: string; scope: LdapScope;
             filter: openArray[byte];
             attributes: openArray[string];
             sizeLimit: int = 0; timeLimit: int = 0):
            tuple[entries: seq[SearchResultEntry]; done: SearchResultDone] =
  let id = c.nextMsgId()
  c.send(buildSearchRequest(id, baseDn, scope, filter = filter,
                             attributes = attributes,
                             sizeLimit = sizeLimit, timeLimit = timeLimit))
  while true:
    let msg = parseLdapMessage(c.recvOne())
    case msg.kind
    of lokSearchResultEntry:
      result.entries.add msg.entry
    of lokSearchResultDone:
      result.done = msg.doneResult
      return
    else:
      raise newException(LdapError, "unexpected response during search")

proc unbind*(c: LdapClient) =
  c.send(buildUnbindRequest(c.nextMsgId()))
  c.close()
