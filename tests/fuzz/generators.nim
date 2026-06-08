## tests/fuzz/generators.nim — structure-aware byte-stream generators.
##
## Plain random bytes spend almost all their iterations failing on the
## very first byte (NTLMSSP magic mismatch, SMB2 magic mismatch, DER
## tag mismatch, ...). These builders produce inputs that pass the
## outer-shell checks so the fuzzer reaches downstream parsing logic.

import std/random

# --- low-level helpers ---------------------------------------------

proc fillRandom*(dst: var openArray[byte]; r: var Rand) =
  for i in 0 ..< dst.len: dst[i] = byte(r.rand(0 .. 255))

proc randomBytes*(r: var Rand; minLen, maxLen: int): seq[byte] =
  let n = r.rand(minLen .. maxLen)
  result = newSeq[byte](n)
  for i in 0 ..< n: result[i] = byte(r.rand(0 .. 255))

# --- DER-aware builder ---------------------------------------------

const DerTagPool* = [
  0x02'u8,  # INTEGER
  0x03'u8,  # BIT STRING
  0x04'u8,  # OCTET STRING
  0x06'u8,  # OID (but with weird content)
  0x0a'u8,  # ENUMERATED
  0x18'u8,  # GeneralizedTime
  0x1b'u8,  # GeneralString
  0x30'u8,  # SEQUENCE
  0x31'u8,  # SET
  0xa0'u8,  # [0] context-specific
  0xa1'u8,  # [1]
  0xa2'u8,  # [2]
  0xa3'u8,  # [3]
  0xa6'u8,  # [6]
  0x60'u8,  # [APPLICATION 0]
  0x61'u8,  # [APPLICATION 1]
  0x6b'u8,  # [APPLICATION 11] (AS-REP)
  0x7e'u8,  # [APPLICATION 30] (KRB-ERROR)
]

proc derLen(out_buf: var seq[byte]; n: int) =
  if n < 0x80:
    out_buf.add byte(n)
  elif n <= 0xff:
    out_buf.add 0x81'u8
    out_buf.add byte(n)
  elif n <= 0xffff:
    out_buf.add 0x82'u8
    out_buf.add byte((n shr 8) and 0xff)
    out_buf.add byte(n and 0xff)
  else:
    out_buf.add 0x83'u8
    out_buf.add byte((n shr 16) and 0xff)
    out_buf.add byte((n shr 8) and 0xff)
    out_buf.add byte(n and 0xff)

proc buildDer*(r: var Rand; depthBudget = 4): seq[byte] =
  ## Generate a syntactically plausible DER blob. Constructed tags
  ## (SEQUENCE, SET, context-class, application-class) recurse on
  ## a randomly-chosen number of children; primitive tags get random
  ## payload bytes. Length encoding is occasionally wrong on purpose
  ## (clamped above) so length-overflow paths still get exercised.
  let tag = DerTagPool[r.rand(0 ..< DerTagPool.len)]
  let constructed = (tag and 0x20'u8) != 0 or (tag and 0xC0'u8) == 0xA0'u8 or
                    (tag and 0xC0'u8) == 0x60'u8
  var payload: seq[byte] = @[]
  if constructed and depthBudget > 0:
    let kids = r.rand(0 .. 4)
    for _ in 0 ..< kids:
      payload.add buildDer(r, depthBudget - 1)
  else:
    let n = r.rand(0 .. 32)
    for _ in 0 ..< n: payload.add byte(r.rand(0 .. 255))
  result = @[tag]
  derLen(result, payload.len)
  result.add payload
  # 10% chance: corrupt the encoded length to a value that doesn't
  # match payload length — drives "read past end" branches.
  if r.rand(0 .. 9) == 0 and result.len > 2:
    result[1] = byte(r.rand(0x80 .. 0xff))

# --- NTLMSSP message builder ---------------------------------------

const NtlmsspMagic* = [byte('N'), byte('T'), byte('L'), byte('M'),
                       byte('S'), byte('S'), byte('P'), 0'u8]

proc buildNtlmsspMessage*(r: var Rand): seq[byte] =
  ## Magic + random msg-type + random body. Drives parseNegotiate /
  ## parseChallenge / parseAuthenticate past the magic check.
  result = @NtlmsspMagic
  let msgType = r.rand(0 .. 4)             # valid types are 1, 2, 3
  result.add byte(msgType)
  result.add byte(0); result.add byte(0); result.add byte(0)   # high bytes of u32
  # Append between 16 and 256 random body bytes.
  let n = r.rand(16 .. 256)
  for _ in 0 ..< n: result.add byte(r.rand(0 .. 255))

# --- SMB2 PDU builder ----------------------------------------------

const Smb2Magic* = [0xFE'u8, byte('S'), byte('M'), byte('B')]

proc buildSmb2Pdu*(r: var Rand): seq[byte] =
  ## Magic + valid 64-byte SMB2 header skeleton + random body.
  result = @Smb2Magic
  result.add 0x40'u8; result.add 0x00'u8        # StructureSize = 64
  # Random credits + status + command (valid range)
  for _ in 0 ..< 2: result.add byte(r.rand(0 .. 255))
  for _ in 0 ..< 4: result.add byte(r.rand(0 .. 255))
  result.add byte(r.rand(0 .. 11))              # command 0..0x0B
  result.add 0'u8
  for _ in 0 ..< 2: result.add byte(r.rand(0 .. 255))
  for _ in 0 ..< 4: result.add byte(r.rand(0 .. 255))
  for _ in 0 ..< 4: result.add byte(r.rand(0 .. 255))    # nextCommand
  for _ in 0 ..< 8: result.add byte(r.rand(0 .. 255))    # messageId
  result.add 0xFF'u8; result.add 0xFE'u8                # Reserved magic
  result.add 0'u8; result.add 0'u8
  for _ in 0 ..< 4: result.add byte(r.rand(0 .. 255))    # treeId
  for _ in 0 ..< 8: result.add byte(r.rand(0 .. 255))    # sessionId
  for _ in 0 ..< 16: result.add byte(r.rand(0 .. 255))   # signature
  # Body: 8..256 random bytes
  let bodyLen = r.rand(8 .. 256)
  for _ in 0 ..< bodyLen: result.add byte(r.rand(0 .. 255))

# --- DCE-RPC PDU builder -------------------------------------------

proc buildRpcPdu*(r: var Rand): seq[byte] =
  ## Valid v5.0 header magic + LE DREP + random body fields.
  result = @[5'u8, 0'u8]                       # rpc_vers, rpc_vers_minor
  result.add byte(r.rand(0 .. 19))             # PTYPE (valid range 0..19)
  result.add byte(r.rand(0 .. 255))            # pfc_flags
  result.add @[0x10'u8, 0, 0, 0]               # LE DREP
  # frag_length: aim for plausible value to encourage deeper parsing.
  let bodyLen = r.rand(0 .. 512)
  let frag = uint16(16 + bodyLen)
  result.add byte(frag and 0xff)
  result.add byte((frag shr 8) and 0xff)
  for _ in 0 ..< 2: result.add byte(r.rand(0 .. 255))    # auth_length
  for _ in 0 ..< 4: result.add byte(r.rand(0 .. 255))    # call_id
  for _ in 0 ..< bodyLen: result.add byte(r.rand(0 .. 255))

# --- LDAP envelope builder -----------------------------------------

proc buildKrbMessage*(r: var Rand; appTag: byte): seq[byte] =
  ## Build something that looks like a Kerberos KRB-* envelope:
  ##   [APPLICATION appTag] SEQUENCE { ... random tagged fields ... }
  ## Used to drive parseAsRep / parseKrbError past the outer tag check.
  var inner: seq[byte] = @[]
  let kids = r.rand(1 .. 6)
  for _ in 0 ..< kids:
    inner.add buildDer(r, depthBudget = 2)
  var seqBlob: seq[byte] = @[0x30'u8]
  derLen(seqBlob, inner.len)
  seqBlob.add inner
  result = @[appTag]
  derLen(result, seqBlob.len)
  result.add seqBlob

proc buildLdapMessage*(r: var Rand): seq[byte] =
  ## SEQUENCE { INTEGER messageId, op } where op is a random
  ## context-tagged blob (a real LDAP op tag is 0x60..0x67).
  var msgIdBytes: seq[byte] = @[]
  let id = r.rand(1 .. 0xffff)
  if id < 0x80:
    msgIdBytes.add byte(id)
  elif id < 0x8000:
    msgIdBytes.add byte((id shr 8) and 0xff)
    msgIdBytes.add byte(id and 0xff)
  else:
    msgIdBytes.add 0'u8
    msgIdBytes.add byte((id shr 8) and 0xff)
    msgIdBytes.add byte(id and 0xff)
  var inner = newSeq[byte](0)
  inner.add 0x02'u8
  inner.add byte(msgIdBytes.len)
  inner.add msgIdBytes
  # Random LDAP op
  let opTag = byte(0x60 + r.rand(0 .. 0xf))   # APPLICATION 0..15
  inner.add opTag
  let opBody = r.rand(0 .. 64)
  inner.add byte(opBody)
  for _ in 0 ..< opBody: inner.add byte(r.rand(0 .. 255))
  result.add 0x30'u8                          # outer SEQUENCE
  derLen(result, inner.len)
  result.add inner
