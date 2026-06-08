## ldap/cldap.nim — Connectionless LDAP (RFC 1798) over UDP.
##
## A CLDAP exchange is one-shot: a Search PDU goes out in a UDP
## datagram to port 389, and the server replies with one or more
## datagrams (SearchResultEntry / SearchResultDone). There's no Bind
## first — connectionless LDAP is implicitly anonymous.
##
## Two layers of API:
##
##   1. ``CldapClient`` — a UDP socket with a configurable timeout.
##      ``cldapSearch`` issues any LDAP Search and returns the result
##      entries plus the SearchResultDone.
##
##   2. ``cldapNetlogonPing`` — a one-call helper for the classic AD
##      DC-discovery use case. It builds the well-known netlogon ping
##      filter, sends it, and decodes the binary
##      ``NETLOGON_SAM_LOGON_RESPONSE_EX`` blob the DC returns.

import std/[net, selectors, nativesockets]
import ../common/[buffers, endian]
import messages

{.push warning[HoleEnumConv]: off.}

type
  CldapError* = object of CatchableError

  CldapClient* = ref object
    sock*: Socket
    host*: string
    port*: int
    nextId*: int
    timeoutMs*: int

# --- timeout machinery ----------------------------------------------

proc waitForData(s: Socket; timeoutMs: int): bool =
  ## ``true`` if data arrived within the timeout, ``false`` on timeout.
  ## Uses std/selectors which abstracts epoll/kqueue/IOCP/select.
  let sel = newSelector[int]()
  defer: sel.close()
  sel.registerHandle(int(s.getFd()), {Event.Read}, 0)
  let ready = sel.select(timeoutMs)
  result = ready.len > 0

# --- client construction --------------------------------------------

proc newCldapClient*(host: string; port: int = 389;
                     timeoutMs: int = 3000): CldapClient =
  result = CldapClient(
    sock: newSocket(AF_INET, SOCK_DGRAM, IPPROTO_UDP, buffered = false),
    host: host, port: port,
    nextId: 1, timeoutMs: timeoutMs)
  result.sock.setSockOpt(OptReuseAddr, true)

proc close*(c: CldapClient) =
  try: c.sock.close() except CatchableError: discard

proc nextMsgId*(c: CldapClient): int =
  result = c.nextId; inc c.nextId

# --- core send / recv -----------------------------------------------

proc sendDatagram(c: CldapClient; pdu: openArray[byte]) =
  var s = newString(pdu.len)
  for i, b in pdu: s[i] = char(b)
  c.sock.sendTo(c.host, Port(c.port), s)

proc recvDatagram(c: CldapClient): seq[byte] =
  if not waitForData(c.sock, c.timeoutMs):
    raise newException(CldapError,
      "no CLDAP response from " & c.host & " within " &
      $c.timeoutMs & "ms")
  var data = newString(8192)
  var sender = ""
  var senderPort: Port
  let n = c.sock.recvFrom(data, 8192, sender, senderPort)
  if n <= 0:
    raise newException(CldapError, "CLDAP recvFrom failed")
  data.setLen(n)
  result = newSeq[byte](n)
  for i in 0 ..< n: result[i] = byte(data[i].ord)

# --- raw "send & receive one PDU" ----------------------------------

proc exchange*(c: CldapClient; pdu: openArray[byte]): LdapMessage =
  ## Single round-trip: send ``pdu``, receive one LDAPMessage.
  c.sendDatagram(pdu)
  result = parseLdapMessage(c.recvDatagram())

# --- generic Search -------------------------------------------------

type
  CldapSearchResult* = object
    entries*: seq[SearchResultEntry]
    done*: SearchResultDone

proc cldapSearch*(c: CldapClient; baseDn: string; scope: LdapScope;
                  filter: openArray[byte];
                  attributes: openArray[string]): CldapSearchResult =
  ## Issue an LDAP Search via UDP. Returns whatever entries the server
  ## sent and the SearchResultDone summary. Most CLDAP servers respond
  ## with exactly one entry + one done in one or two datagrams, but we
  ## loop until SearchResultDone arrives or the socket times out.
  let id = c.nextMsgId()
  c.sendDatagram(buildSearchRequest(id, baseDn, scope, filter = filter,
                                     attributes = attributes))
  while true:
    let msg = parseLdapMessage(c.recvDatagram())
    case msg.kind
    of lokSearchResultEntry:
      result.entries.add msg.entry
    of lokSearchResultDone:
      result.done = msg.doneResult
      return
    else:
      raise newException(CldapError,
        "unexpected CLDAP response kind: " & $msg.kind)

# --- NETLOGON_SAM_LOGON_RESPONSE_EX (MS-NRPC §2.2.1.3.13) -----------

type
  NetlogonFlag* = enum
    flagPdc           = 0       # DS_PDC_FLAG — primary DC
    flagGc            = 2       # DS_GC_FLAG — global catalog
    flagLdap          = 3       # DS_LDAP_FLAG
    flagDs            = 4       # DS_DS_FLAG
    flagKdc           = 5       # DS_KDC_FLAG
    flagTimeserv      = 6       # DS_TIMESERV_FLAG
    flagClosest       = 7       # DS_CLOSEST_FLAG
    flagWritable      = 8       # DS_WRITABLE_FLAG
    flagGoodTimeserv  = 9       # DS_GOOD_TIMESERV_FLAG
    flagNdnc          = 10      # DS_NDNC_FLAG
    flagSelectSecret  = 11
    flagFullSecret    = 12
    flagWs            = 13
    flagDns           = 29      # response uses DNS names
    flagDnsDomain     = 30
    flagDnsForest     = 31

  NetlogonFlags* = set[NetlogonFlag]

  NetlogonResponse* = object
    opcode*: uint16
    sbz*: uint16
    flags*: NetlogonFlags
    domainGuid*: array[16, byte]
    dnsForest*: string
    dnsDomain*: string
    dnsHostname*: string
    netbiosDomain*: string
    netbiosHostname*: string
    userName*: string
    dcSiteName*: string
    clientSiteName*: string
    version*: uint32
    lmNtToken*: uint16
    lm20Token*: uint16

# --- DNS-style compressed-name decoding (RFC 1035 §4.1.4) -----------

proc readCompressedName(data: openArray[byte]; pos: var int): string =
  result = ""
  var jumped = false
  var savedPos = pos
  while pos < data.len:
    let b = data[pos]
    if b == 0:
      inc pos
      break
    if (b and 0xC0) == 0xC0:
      if pos + 1 >= data.len: break
      let off = (int(b and 0x3F) shl 8) or int(data[pos + 1])
      pos += 2
      if not jumped:
        savedPos = pos
        jumped = true
      pos = off
      continue
    let labLen = int(b)
    inc pos
    if pos + labLen > data.len: break
    if result.len > 0: result.add '.'
    for i in 0 ..< labLen:
      result.add char(data[pos + i])
    pos += labLen
  if jumped: pos = savedPos

const NetlogonResponseExOpcode = 23'u16

proc parseNetlogonResponse*(blob: openArray[byte]): NetlogonResponse =
  ## Parse NETLOGON_SAM_LOGON_RESPONSE_EX (opcode 23 / 0x17). Anything
  ## else is best-effort — most fields will be unreliable.
  if blob.len < 8:
    raise newException(CldapError, "netlogon response too short")
  let b = newBuffer(@blob)
  result.opcode = b.readU16LE()
  result.sbz = b.readU16LE()
  let flagBits = b.readU32LE()
  for i in 0 ..< 32:
    if (flagBits and (1'u32 shl i)) != 0:
      try: result.flags.incl NetlogonFlag(i)
      except RangeDefect: discard
  for i in 0 ..< 16: result.domainGuid[i] = b.readByte()

  var pos = b.pos
  result.dnsForest       = readCompressedName(blob, pos)
  result.dnsDomain       = readCompressedName(blob, pos)
  result.dnsHostname     = readCompressedName(blob, pos)
  result.netbiosDomain   = readCompressedName(blob, pos)
  result.netbiosHostname = readCompressedName(blob, pos)
  result.userName        = readCompressedName(blob, pos)
  result.dcSiteName      = readCompressedName(blob, pos)
  result.clientSiteName  = readCompressedName(blob, pos)
  if pos + 8 <= blob.len:
    b.seek(pos)
    result.version  = b.readU32LE()
    result.lmNtToken = b.readU16LE()
    result.lm20Token = b.readU16LE()

# --- netlogon filter + ping helper ---------------------------------

proc buildNetlogonQuery*(dnsDomain, netbiosDomain, host: string;
                        userName: string = "";
                        ntVer: uint32 = 0x00000006): seq[byte] =
  ## Build the AD-style netlogon CLDAP search PDU. ``NtVer = 0x06``
  ## asks for a NETLOGON_SAM_LOGON_RESPONSE_EX (MS-ADTS §6.3.3).
  var parts: seq[seq[byte]] = @[]
  parts.add buildEqualityFilter("NtVer",
              @[byte(ntVer and 0xff), byte((ntVer shr 8) and 0xff),
                byte((ntVer shr 16) and 0xff), byte((ntVer shr 24) and 0xff)])
  if dnsDomain.len > 0:
    parts.add buildEqualityFilter("DnsDomain", cast[seq[byte]](dnsDomain))
  if netbiosDomain.len > 0:
    parts.add buildEqualityFilter("DomainSid", cast[seq[byte]](netbiosDomain))
  if host.len > 0:
    parts.add buildEqualityFilter("Host", cast[seq[byte]](host))
  if userName.len > 0:
    parts.add buildEqualityFilter("User", cast[seq[byte]](userName))
  let filter = buildAndFilter(parts)
  result = buildSearchRequest(messageId = 1, baseDn = "",
                               scope = lsBaseObject,
                               filter = filter,
                               attributes = @["netlogon"])

proc cldapNetlogonPing*(host: string; dnsDomain: string = "";
                        timeoutMs: int = 3000;
                        port: int = 389): NetlogonResponse =
  ## One-call AD discovery. Convenience wrapper around the generic
  ## CldapClient + cldapSearch path.
  let c = newCldapClient(host, port, timeoutMs)
  defer: c.close()
  let pdu = buildNetlogonQuery(dnsDomain = dnsDomain,
                                netbiosDomain = "", host = "")
  let msg = c.exchange(pdu)
  case msg.kind
  of lokSearchResultEntry:
    for attr in msg.entry.attributes:
      if attr.name == "netlogon" or attr.name == "Netlogon":
        if attr.values.len > 0:
          return parseNetlogonResponse(attr.values[0])
    raise newException(CldapError, "no netlogon attribute in response")
  else:
    raise newException(CldapError,
      "expected SearchResultEntry, got " & $msg.kind)

# --- pretty-print helpers (handy for the cldapquery tool) ---------

proc `$`*(f: NetlogonFlag): string =
  case f
  of flagPdc: "PDC"
  of flagGc: "GC"
  of flagLdap: "LDAP"
  of flagDs: "DS"
  of flagKdc: "KDC"
  of flagTimeserv: "Timeserv"
  of flagClosest: "Closest"
  of flagWritable: "Writable"
  of flagGoodTimeserv: "GoodTimeserv"
  of flagNdnc: "NDNC"
  of flagSelectSecret: "SelectSecret"
  of flagFullSecret: "FullSecret"
  of flagWs: "WS"
  of flagDns: "DNS"
  of flagDnsDomain: "DnsDomain"
  of flagDnsForest: "DnsForest"

proc `$`*(s: NetlogonFlags): string =
  result = "{"
  var first = true
  for f in s:
    if not first: result.add ","
    result.add $f
    first = false
  result.add "}"

{.pop.}
