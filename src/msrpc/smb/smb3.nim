## smb/smb3.nim — SMB 3.x dialect support: negotiate contexts, signing
## (AES-CMAC for 3.0/3.0.2, AES-CMAC also valid for 3.1.1), encryption
## via AES-128-CCM, session-key derivation via SP 800-108 KBKDF.
##
## Layered on top of the existing smb/client.nim — its NEGOTIATE and
## SESSION_SETUP routines call into here when a 3.x dialect is being
## offered or has been negotiated. AES-GCM (added in 3.1.1) is left to
## a follow-up; AES-CCM works across all 3.x versions.

import ../common/[buffers, endian]
import ../crypto/[aes_cmac, aes_ccm, kdf]

# --- dialect identifiers (MS-SMB2 §2.2.3) ---------------------------

const
  Smb202* = 0x0202'u16
  Smb210* = 0x0210'u16
  Smb300* = 0x0300'u16
  Smb302* = 0x0302'u16
  Smb311* = 0x0311'u16

# --- negotiate context types (3.1.1 only) --------------------------

const
  CtxPreauthIntegrity* = 0x0001'u16
  CtxEncryption*       = 0x0002'u16
  CtxCompression*      = 0x0003'u16
  CtxNetname*          = 0x0005'u16

# --- cipher identifiers --------------------------------------------

const
  AesCcm128*  = 0x0001'u16
  AesGcm128*  = 0x0002'u16
  AesCcm256*  = 0x0003'u16
  AesGcm256*  = 0x0004'u16

# --- hash algorithm identifiers ------------------------------------

const HashSha512* = 0x0001'u16

# --- key-derivation labels (MS-SMB2 §3.1.4.2) ----------------------
#
# SMB 3.0 / 3.0.2:
#   SigningKey       = KDF(SessionKey, "SMB2AESCMAC\0",   "SmbSign\0")
#   ApplicationKey   = KDF(SessionKey, "SMB2APP\0",       "SmbRpc\0")
#   EncryptionKey    = KDF(SessionKey, "SMB2AESCCM\0",    "ServerIn \0")
#   DecryptionKey    = KDF(SessionKey, "SMB2AESCCM\0",    "ServerOut\0")
#
# SMB 3.1.1:
#   SigningKey       = KDF(SessionKey, "SMBSigningKey\0", PreauthHash)
#   ApplicationKey   = KDF(SessionKey, "SMBAppKey\0",     PreauthHash)
#   EncryptionKey    = KDF(SessionKey, "SMBC2SCipherKey\0", PreauthHash)
#   DecryptionKey    = KDF(SessionKey, "SMBS2CCipherKey\0", PreauthHash)
#
# (PreauthHash = running SHA-512 of all NEGOTIATE+SESSION_SETUP messages.)

const
  Lbl30Signing*    = "SMB2AESCMAC\0"
  Ctx30Signing*    = "SmbSign\0"
  Lbl30AppKey*     = "SMB2APP\0"
  Ctx30AppKey*     = "SmbRpc\0"
  Lbl30Encrypt*    = "SMB2AESCCM\0"
  Ctx30ServerIn*   = "ServerIn \0"      # note trailing space
  Ctx30ServerOut*  = "ServerOut\0"

  Lbl311Signing*   = "SMBSigningKey\0"
  Lbl311AppKey*    = "SMBAppKey\0"
  Lbl311CipherC2S* = "SMBC2SCipherKey\0"
  Lbl311CipherS2C* = "SMBS2CCipherKey\0"

# Negotiate-context list serialization ------------------------------

proc writeNegotiateContext*(b: Buffer; ctxType: uint16; data: openArray[byte]) =
  ## SMB2_NEGOTIATE_CONTEXT structure: type/u16, dataLen/u16, reserved/u32,
  ## then ``dataLen`` bytes of data, padded to 8-byte boundary.
  b.writeU16LE(ctxType)
  b.writeU16LE(uint16(data.len))
  b.writeU32LE(0)
  b.writeBytes(data)
  while (b.pos and 7) != 0:
    b.writeByte(0)

proc buildPreauthIntegrityContext*(hashAlgs: openArray[uint16];
                                    salt: openArray[byte]): seq[byte] =
  let b = newBuffer()
  b.writeU16LE(uint16(hashAlgs.len))     # HashAlgorithmCount
  b.writeU16LE(uint16(salt.len))         # SaltLength
  for a in hashAlgs: b.writeU16LE(a)
  b.writeBytes(salt)
  result = b.consumed

proc buildEncryptionContext*(ciphers: openArray[uint16]): seq[byte] =
  let b = newBuffer()
  b.writeU16LE(uint16(ciphers.len))
  for c in ciphers: b.writeU16LE(c)
  result = b.consumed

# --- session-key derivation ---------------------------------------

proc derive30Keys*(sessionKey: openArray[byte]):
                   tuple[signing, encrypt, decrypt, appKey: seq[byte]] =
  ## Returns four 16-byte keys derived per the SMB 3.0 / 3.0.2 rules.
  result.signing = kdfCounter256(sessionKey,
                                   cast[seq[byte]](@Lbl30Signing),
                                   cast[seq[byte]](@Ctx30Signing), 16)
  result.encrypt = kdfCounter256(sessionKey,
                                   cast[seq[byte]](@Lbl30Encrypt),
                                   cast[seq[byte]](@Ctx30ServerIn), 16)
  result.decrypt = kdfCounter256(sessionKey,
                                   cast[seq[byte]](@Lbl30Encrypt),
                                   cast[seq[byte]](@Ctx30ServerOut), 16)
  result.appKey  = kdfCounter256(sessionKey,
                                   cast[seq[byte]](@Lbl30AppKey),
                                   cast[seq[byte]](@Ctx30AppKey), 16)

proc derive311Keys*(sessionKey, preauthHash: openArray[byte]):
                    tuple[signing, encrypt, decrypt, appKey: seq[byte]] =
  ## SMB 3.1.1 derivation. ``preauthHash`` is the 64-byte SHA-512 over
  ## all NEGOTIATE + SESSION_SETUP messages exchanged so far.
  result.signing = kdfCounter256(sessionKey,
                                   cast[seq[byte]](@Lbl311Signing),
                                   preauthHash, 16)
  result.encrypt = kdfCounter256(sessionKey,
                                   cast[seq[byte]](@Lbl311CipherC2S),
                                   preauthHash, 16)
  result.decrypt = kdfCounter256(sessionKey,
                                   cast[seq[byte]](@Lbl311CipherS2C),
                                   preauthHash, 16)
  result.appKey  = kdfCounter256(sessionKey,
                                   cast[seq[byte]](@Lbl311AppKey),
                                   preauthHash, 16)

# --- per-message signing ------------------------------------------

proc signMessage*(signingKey, message: openArray[byte]): array[16, byte] =
  ## SMB 3.x signing: AES-CMAC over the entire SMB2 PDU with the
  ## signature field zeroed. Callers must blank bytes 48..63 of the
  ## header before passing in.
  result = aesCmac128(signingKey, message)

# --- per-message encryption (TRANSFORM_HEADER + AES-CCM) ---------

const TransformHeaderLen* = 52

type
  TransformHeader* = object
    signature*: array[16, byte]
    nonce*: array[16, byte]        ## first 11 bytes are the CCM nonce
    originalSize*: uint32
    reserved*: uint16
    flags*: uint16                 ## 0x0001 = encryption algorithm 1 (CCM)
    sessionId*: uint64

proc writeTransformHeader*(b: Buffer; h: TransformHeader) =
  ## Protocol ID then signature, nonce, fields. The transform header
  ## sits in front of the encrypted SMB2 payload on the wire.
  b.writeBytes([0xFD'u8, byte('S'), byte('M'), byte('B')])
  for x in h.signature: b.writeByte(x)
  for x in h.nonce: b.writeByte(x)
  b.writeU32LE(h.originalSize)
  b.writeU16LE(h.reserved)
  b.writeU16LE(h.flags)
  b.writeU64LE(h.sessionId)

proc readTransformHeader*(b: Buffer): TransformHeader =
  let sig = b.readBytes(4)
  doAssert sig == @[0xFD'u8, byte('S'), byte('M'), byte('B')],
    "missing SMB2 transform header magic"
  for i in 0 ..< 16: result.signature[i] = b.readByte()
  for i in 0 ..< 16: result.nonce[i] = b.readByte()
  result.originalSize = b.readU32LE()
  result.reserved = b.readU16LE()
  result.flags = b.readU16LE()
  result.sessionId = b.readU64LE()

proc encryptPdu*(encryptKey: openArray[byte]; plaintext: openArray[byte];
                 nonce11: openArray[byte]; sessionId: uint64):
                 tuple[transformHeader: seq[byte]; ciphertext: seq[byte]] =
  ## Encrypt one SMB2 PDU. Returns the on-wire bytes: transform
  ## header || ciphertext. AAD covers fields 20..51 of the transform
  ## header (everything except ProtocolId and Signature).
  doAssert nonce11.len == 11
  # Build the AAD: nonce(16; 11 used + 5 pad of zeros) || originalSize ||
  # reserved || flags || sessionId. Total 32 bytes.
  var aad = newSeq[byte](32)
  for i in 0 ..< 11: aad[i] = nonce11[i]
  # bytes 11..15 = 0 (nonce padding)
  let osz = plaintext.len
  aad[16] = byte(osz and 0xff)
  aad[17] = byte((osz shr 8) and 0xff)
  aad[18] = byte((osz shr 16) and 0xff)
  aad[19] = byte((osz shr 24) and 0xff)
  # reserved 20..21 = 0
  aad[22] = 0x01                           # flags = encrypted
  aad[23] = 0x00
  for i in 0 ..< 8:
    aad[24 + i] = byte((sessionId shr (i * 8)) and 0xff)

  let (ct, tag) = ccmEncrypt(encryptKey, nonce11, aad, plaintext, tagLen = 16)

  let hb = newBuffer()
  hb.writeBytes([0xFD'u8, byte('S'), byte('M'), byte('B')])
  for x in tag: hb.writeByte(x)             # signature = AES-CCM tag
  for i in 0 ..< 11: hb.writeByte(nonce11[i])
  for _ in 0 ..< 5: hb.writeByte(0)
  hb.writeU32LE(uint32(osz))
  hb.writeU16LE(0)
  hb.writeU16LE(0x0001)
  hb.writeU64LE(sessionId)
  result = (transformHeader: hb.consumed, ciphertext: ct)

proc decryptPdu*(decryptKey: openArray[byte];
                 transformHeader, ciphertext: openArray[byte]):
                 tuple[plaintext: seq[byte]; ok: bool] =
  ## Verify+decrypt an inbound encrypted PDU.
  doAssert transformHeader.len == TransformHeaderLen
  let b = newBuffer(@transformHeader)
  let header = b.readTransformHeader()
  var nonce11: array[11, byte]
  for i in 0 ..< 11: nonce11[i] = header.nonce[i]
  var aad = newSeq[byte](32)
  for i in 0 ..< 32: aad[i] = transformHeader[20 + i]
  var tag = newSeq[byte](16)
  for i in 0 ..< 16: tag[i] = header.signature[i]
  let (pt, ok) = ccmDecrypt(decryptKey, nonce11, aad, ciphertext, tag)
  result.plaintext = pt
  result.ok = ok
