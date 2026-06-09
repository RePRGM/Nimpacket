## keytab.nim — MIT Kerberos keytab (FILE:) v2 reader/writer.
##
## A keytab stores long-term keys for service principals (and, for tooling,
## extracted account keys). This is the format `ktutil`, `kinit -k`, and
## impacket's ``impacket.krb5.keytab`` read and write.
##
## Only file-format version 2 (magic ``0x0502``, big-endian) is implemented.
## It differs from the credential cache in three ways worth noting:
##   * counted strings are length-prefixed with a uint16, not a uint32;
##   * each entry is prefixed by a signed int32 size (negative = a deleted
##     "hole" that ktutil leaves in place);
##   * the principal's name-type trails the components instead of leading.
##
## Reference: https://repo.or.cz/w/krb5dissect.git/blob_plain/HEAD:/keytab.txt
## Cross-validated byte-for-byte against impacket's keytab reader.

import std/strutils
import msrpc/common/buffers
import msrpc/common/endian

const KeytabV2Magic* = 0x0502'u16

type
  KeytabError* = object of CatchableError

  KtPrincipal* = object
    nameType*: uint32
    realm*: string
    components*: seq[string]

  KtEntry* = object
    deleted*: bool          ## true for a ktutil "hole" (negative size on disk)
    principal*: KtPrincipal
    timestamp*: uint32      ## key creation time (Unix seconds)
    vno8*: uint8            ## low byte of the key version number
    keytype*: uint16        ## Kerberos etype (e.g. 18 = AES256)
    key*: seq[byte]
    rest*: seq[byte]        ## trailing entry bytes (usually the 4-byte uint32 kvno)

  Keytab* = object
    entries*: seq[KtEntry]

# --- helpers ----------------------------------------------------------------

proc fail(msg: string) {.noreturn.} =
  raise newException(KeytabError, msg)

proc writeI32BE(b: Buffer; v: int32) {.inline.} = b.writeU32BE(cast[uint32](v))
proc readI32BE(b: Buffer): int32 {.inline.} = cast[int32](b.readU32BE())

proc writeCounted16(b: Buffer; data: openArray[byte]) =
  if data.len > 0xffff: fail("counted string too long for a uint16 length")
  b.writeU16BE(uint16(data.len))
  b.writeBytes(data)

proc readCounted16(b: Buffer): seq[byte] =
  let n = b.readU16BE()
  result = b.readBytes(int(n))

proc toStr(data: seq[byte]): string =
  result = newString(data.len)
  for i, c in data: result[i] = char(c)

# --- principal --------------------------------------------------------------

proc writePrincipal(b: Buffer; p: KtPrincipal) =
  b.writeU16BE(uint16(p.components.len))
  b.writeCounted16(p.realm.toOpenArrayByte(0, p.realm.high))
  for c in p.components:
    b.writeCounted16(c.toOpenArrayByte(0, c.high))
  b.writeU32BE(p.nameType)        # name-type trails the components in a keytab

proc readPrincipal(b: Buffer): KtPrincipal =
  let n = b.readU16BE()
  result.realm = toStr(b.readCounted16())
  for _ in 0'u16 ..< n:
    result.components.add toStr(b.readCounted16())
  result.nameType = b.readU32BE()

proc prettyName*(p: KtPrincipal): string =
  ## "host/server.example.com@EXAMPLE.COM" or "alice@EXAMPLE.COM".
  result = p.components.join("/")
  result.add '@'
  result.add p.realm

# --- entry kvno -------------------------------------------------------------

proc kvno*(e: KtEntry): uint32 =
  ## The effective key version number: the 4-byte trailer when present and
  ## non-zero, otherwise the single-byte ``vno8`` (matches MIT/impacket).
  if e.rest.len >= 4 and (e.rest[0] or e.rest[1] or e.rest[2] or e.rest[3]) != 0:
    result = (uint32(e.rest[0]) shl 24) or (uint32(e.rest[1]) shl 16) or
             (uint32(e.rest[2]) shl 8) or uint32(e.rest[3])
  else:
    result = uint32(e.vno8)

proc ktEntry*(principal: KtPrincipal; keytype: uint16; key: openArray[byte];
              timestamp: uint32; kvno: uint32 = 1): KtEntry =
  ## Build a live keytab entry, emitting the standard 4-byte kvno trailer so
  ## key version numbers above 255 survive.
  result = KtEntry(
    deleted: false, principal: principal, timestamp: timestamp,
    vno8: uint8(kvno and 0xff), keytype: keytype, key: @key,
    rest: @[byte(kvno shr 24), byte(kvno shr 16), byte(kvno shr 8), byte(kvno)])

# --- container --------------------------------------------------------------

proc encodeEntry(b: Buffer; e: KtEntry) =
  let body = newBuffer()
  body.writePrincipal(e.principal)
  body.writeU32BE(e.timestamp)
  body.writeU8(e.vno8)
  body.writeU16BE(e.keytype)
  body.writeCounted16(e.key)
  body.writeBytes(e.rest)
  let full = body.bytes
  b.writeI32BE(if e.deleted: -int32(full.len) else: int32(full.len))
  b.writeBytes(full)

proc encodeKeytab*(kt: Keytab): seq[byte] =
  let b = newBuffer()
  b.writeU16BE(KeytabV2Magic)
  for e in kt.entries:
    b.encodeEntry(e)
  result = b.bytes

proc parseKeytab*(data: openArray[byte]): Keytab =
  ## Parse a v2 keytab. Raises ``KeytabError`` on malformed/unsupported input.
  let b = newBuffer(data)
  if b.remaining < 2:
    fail("truncated: no file-format version")
  let magic = b.readU16BE()
  if magic != KeytabV2Magic:
    if magic shr 8 == 0x05 and (magic and 0xff) == 1:
      fail("keytab file-format version 1 is not supported (only v2 / 0x0502)")
    fail("not a v2 keytab: magic 0x" & magic.int.toHex(4))
  try:
    while not b.atEnd:
      let size = b.readI32BE()
      let elen = abs(int(size))
      let entryBytes = b.readBytes(elen)   # consumes exactly the whole entry
      let eb = newBuffer(entryBytes)
      var e: KtEntry
      e.deleted = size < 0
      e.principal = eb.readPrincipal()
      e.timestamp = eb.readU32BE()
      e.vno8 = eb.readU8()
      e.keytype = eb.readU16BE()
      e.key = eb.readCounted16()
      e.rest = eb.readBytes(eb.remaining)
      result.entries.add e
  except BufferRangeError as e:
    fail("truncated or malformed keytab: " & e.msg)
