## ccache.nim — MIT Kerberos credential cache (FILE:) v4 reader/writer.
##
## Implements the on-disk format that `klist`, `kinit`, and impacket read
## and write via the ``KRB5CCNAME`` environment variable, so tickets this
## library obtains (AS-REP / TGS-REP) can be handed to the standard Kerberos
## toolchain and vice-versa.
##
## Only file-format version 4 (magic ``0x0504``, big-endian) is implemented;
## that is what every current MIT/Heimdal/impacket build emits. Versions 1–3
## are rejected with a clear error.
##
## Reference: https://web.mit.edu/kerberos/krb5-devel/doc/formats/ccache_file_format.html
## Cross-validated byte-for-byte against impacket's ``impacket.krb5.ccache``.

import std/strutils
import msrpc/common/buffers
import msrpc/common/endian

const
  CcacheV4Magic* = 0x0504'u16
  HdrTagDeltaTime* = 0x0001'u16   ## the one header tag MIT/impacket emit

type
  CcacheError* = object of CatchableError
    ## Raised on a malformed or unsupported credential cache.

  CcHeader* = object
    ## A raw file-header field (tag/value). Preserved verbatim so an
    ## unknown header round-trips unchanged.
    tag*: uint16
    data*: seq[byte]

  CcPrincipal* = object
    nameType*: uint32
    realm*: string
    components*: seq[string]

  CcKeyBlock* = object
    keytype*: uint16        ## Kerberos etype of the session key (e.g. 18 = AES256)
    etype*: uint16          ## v4's second (historically unused) etype slot; usually 0
    key*: seq[byte]

  CcTimes* = object
    authtime*, starttime*, endtime*, renewTill*: uint32

  CcAddress* = object
    addrType*: uint16
    data*: seq[byte]

  CcAuthData* = object
    adType*: uint16
    data*: seq[byte]

  CcCredential* = object
    client*: CcPrincipal
    server*: CcPrincipal
    key*: CcKeyBlock
    times*: CcTimes
    isSkey*: bool
    tktFlags*: uint32
    addresses*: seq[CcAddress]
    authData*: seq[CcAuthData]
    ticket*: seq[byte]        ## DER-encoded Ticket
    secondTicket*: seq[byte]  ## second ticket (S4U2proxy / user-to-user); empty if none

  Ccache* = object
    headers*: seq[CcHeader]
    defaultPrincipal*: CcPrincipal
    credentials*: seq[CcCredential]

# --- helpers ----------------------------------------------------------------

proc fail(msg: string) {.noreturn.} =
  raise newException(CcacheError, msg)

proc writeCounted(b: Buffer; data: openArray[byte]) =
  ## counted_octet_string: 4-byte big-endian length, then the bytes.
  b.writeU32BE(uint32(data.len))
  b.writeBytes(data)

proc readCounted(b: Buffer): seq[byte] =
  let n = b.readU32BE()
  if n > uint32(b.remaining):
    fail("counted_octet_string length " & $n & " exceeds " & $b.remaining & " remaining")
  result = b.readBytes(int(n))

proc toStr(data: seq[byte]): string =
  result = newString(data.len)
  for i, c in data: result[i] = char(c)

# --- principal --------------------------------------------------------------

proc writePrincipal*(b: Buffer; p: CcPrincipal) =
  b.writeU32BE(p.nameType)
  b.writeU32BE(uint32(p.components.len))
  b.writeCounted(p.realm.toOpenArrayByte(0, p.realm.high))
  for c in p.components:
    b.writeCounted(c.toOpenArrayByte(0, c.high))

proc readPrincipal*(b: Buffer): CcPrincipal =
  result.nameType = b.readU32BE()
  let n = b.readU32BE()
  if n > uint32(b.remaining):
    fail("principal component count " & $n & " is implausible")
  result.realm = toStr(b.readCounted())
  for _ in 0'u32 ..< n:
    result.components.add toStr(b.readCounted())

proc prettyName*(p: CcPrincipal): string =
  ## "alice@EXAMPLE.COM" or "krbtgt/EXAMPLE.COM@EXAMPLE.COM".
  result = p.components.join("/")
  result.add '@'
  result.add p.realm

# --- credential -------------------------------------------------------------

proc writeKeyBlock(b: Buffer; k: CcKeyBlock) =
  b.writeU16BE(k.keytype)
  b.writeU16BE(k.etype)
  b.writeU16BE(uint16(k.key.len))
  b.writeBytes(k.key)

proc readKeyBlock(b: Buffer): CcKeyBlock =
  result.keytype = b.readU16BE()
  result.etype = b.readU16BE()
  let n = b.readU16BE()
  result.key = b.readBytes(int(n))

proc writeCredential*(b: Buffer; c: CcCredential) =
  b.writePrincipal(c.client)
  b.writePrincipal(c.server)
  b.writeKeyBlock(c.key)
  b.writeU32BE(c.times.authtime)
  b.writeU32BE(c.times.starttime)
  b.writeU32BE(c.times.endtime)
  b.writeU32BE(c.times.renewTill)
  b.writeU8(if c.isSkey: 1'u8 else: 0'u8)
  b.writeU32BE(c.tktFlags)
  b.writeU32BE(uint32(c.addresses.len))
  for a in c.addresses:
    b.writeU16BE(a.addrType)
    b.writeCounted(a.data)
  b.writeU32BE(uint32(c.authData.len))
  for ad in c.authData:
    b.writeU16BE(ad.adType)
    b.writeCounted(ad.data)
  b.writeCounted(c.ticket)
  b.writeCounted(c.secondTicket)

proc readCredential*(b: Buffer): CcCredential =
  result.client = b.readPrincipal()
  result.server = b.readPrincipal()
  result.key = b.readKeyBlock()
  result.times.authtime = b.readU32BE()
  result.times.starttime = b.readU32BE()
  result.times.endtime = b.readU32BE()
  result.times.renewTill = b.readU32BE()
  result.isSkey = b.readU8() != 0
  result.tktFlags = b.readU32BE()
  let nAddr = b.readU32BE()
  for _ in 0'u32 ..< nAddr:
    var a: CcAddress
    a.addrType = b.readU16BE()
    a.data = b.readCounted()
    result.addresses.add a
  let nAuth = b.readU32BE()
  for _ in 0'u32 ..< nAuth:
    var ad: CcAuthData
    ad.adType = b.readU16BE()
    ad.data = b.readCounted()
    result.authData.add ad
  result.ticket = b.readCounted()
  result.secondTicket = b.readCounted()

# --- container --------------------------------------------------------------

proc defaultCcache*(principal: CcPrincipal): Ccache =
  ## A cache with the single DeltaTime header MIT/impacket emit
  ## (offset 0xffffffff / 0), the given default principal, no credentials.
  result.headers = @[CcHeader(tag: HdrTagDeltaTime,
                              data: @[0xff'u8, 0xff, 0xff, 0xff, 0, 0, 0, 0])]
  result.defaultPrincipal = principal

proc encodeCcache*(cc: Ccache): seq[byte] =
  ## Serialize to the v4 wire format (suitable for writing to a FILE: cache).
  # Header block is length-prefixed, so build it first to measure it.
  let hb = newBuffer()
  for h in cc.headers:
    hb.writeU16BE(h.tag)
    hb.writeU16BE(uint16(h.data.len))
    hb.writeBytes(h.data)
  let headerBytes = hb.bytes

  let b = newBuffer()
  b.writeU16BE(CcacheV4Magic)
  b.writeU16BE(uint16(headerBytes.len))
  b.writeBytes(headerBytes)
  b.writePrincipal(cc.defaultPrincipal)
  for c in cc.credentials:
    b.writeCredential(c)
  result = b.bytes

proc parseCcache*(data: openArray[byte]): Ccache =
  ## Parse a v4 credential cache. Raises ``CcacheError`` on bad/unsupported input.
  let b = newBuffer(data)
  if b.remaining < 2:
    fail("truncated: no file-format version")
  let magic = b.readU16BE()
  if magic != CcacheV4Magic:
    let ver = magic and 0x00ff'u16
    if magic shr 8 == 0x05 and ver in {1'u16, 2, 3}:
      fail("ccache file-format version " & $ver & " is not supported (only v4 / 0x0504)")
    fail("not a v4 ccache: magic 0x" & magic.int.toHex(4))
  # Past the magic, any buffer overrun means the cache is truncated/malformed;
  # surface it as CcacheError so callers only need to catch one error type.
  try:
    let headerLen = int(b.readU16BE())
    if headerLen > b.remaining:
      fail("header length " & $headerLen & " exceeds buffer")
    let headerEnd = b.pos + headerLen
    while b.pos < headerEnd:
      var h: CcHeader
      h.tag = b.readU16BE()
      let tl = int(b.readU16BE())
      if b.pos + tl > headerEnd:
        fail("header tag " & $h.tag & " overruns the header block")
      h.data = b.readBytes(tl)
      result.headers.add h
    result.defaultPrincipal = b.readPrincipal()
    while not b.atEnd:
      result.credentials.add b.readCredential()
  except BufferRangeError as e:
    fail("truncated or malformed ccache: " & e.msg)
