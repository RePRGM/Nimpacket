## auth/kerberos/preauth.nim — PA-ENC-TIMESTAMP construction.
##
## When a KDC returns KDC_ERR_PREAUTH_REQUIRED on a no-PA AS-REQ, the
## client retries with a PA-DATA list containing a PA-ENC-TIMESTAMP:
## an encrypted current timestamp that proves the client knows the
## password. The encryption uses the user's long-term key with key
## usage = 1 (RFC 4120 §7.5.1).
##
## EncryptedData ::= SEQUENCE {
##     etype  [0] Int32,
##     kvno   [1] UInt32 OPTIONAL,
##     cipher [2] OCTET STRING }
##
## PA-ENC-TS-ENC ::= SEQUENCE {
##     patimestamp [0] KerberosTime,
##     pausec      [1] Microseconds OPTIONAL }
##
## We support RC4-HMAC (ETYPE 23) directly; AES-CTS would require
## the full DK + cf2-mixed key derivation pipeline that's a separate
## chunk of work.

import std/times
import ../../common/buffers
import ../spnego/asn1
import rc4 as krbRc4
import aes as krbAes
import etype
import messages   # for fieldTag, kerberosTimestamp

# --- ASN.1 EncryptedData -------------------------------------------

proc buildEncryptedData*(etype: uint32; cipher: openArray[byte];
                        kvno: int = -1): seq[byte] =
  ## EncryptedData ::= SEQUENCE {
  ##   etype  [0] Int32,
  ##   kvno   [1] UInt32 OPTIONAL,
  ##   cipher [2] OCTET STRING }
  let inner = newBuffer()
  # [0] etype
  var etypeBytes: seq[byte] = @[]
  var v = etype
  while v > 0:
    etypeBytes.insert(byte(v and 0xff), 0)
    v = v shr 8
  if etypeBytes.len == 0: etypeBytes = @[0'u8]
  if (etypeBytes[0] and 0x80) != 0: etypeBytes.insert(0'u8, 0)
  inner.writeBytes(fieldTag(0, derTLV(0x02'u8, etypeBytes)))
  # [1] kvno (optional)
  if kvno >= 0:
    var kvnoBytes: seq[byte] = @[]
    var k = kvno
    while k > 0:
      kvnoBytes.insert(byte(k and 0xff), 0)
      k = k shr 8
    if kvnoBytes.len == 0: kvnoBytes = @[0'u8]
    if (kvnoBytes[0] and 0x80) != 0: kvnoBytes.insert(0'u8, 0)
    inner.writeBytes(fieldTag(1, derTLV(0x02'u8, kvnoBytes)))
  # [2] cipher
  inner.writeBytes(fieldTag(2, derTLV(tagOctetString, cipher)))
  result = derTLV(tagSequence, inner.consumed)

# --- PA-ENC-TS-ENC ------------------------------------------------

proc buildPaEncTsEnc*(t: Time): seq[byte] =
  ## Plaintext PA-ENC-TS-ENC (before encryption). One required field.
  let inner = newBuffer()
  inner.writeBytes(fieldTag(0,
    derTLV(0x18'u8, cast[seq[byte]](kerberosTimestamp(t)))))
  # pausec is optional and almost never sent.
  result = derTLV(tagSequence, inner.consumed)

# --- PA-ENC-TIMESTAMP using RC4-HMAC -------------------------------

proc buildPaEncTimestampRc4*(baseKey: openArray[byte]; t: Time): seq[byte] =
  ## The full PA-DATA value for PA-ENC-TIMESTAMP under RC4-HMAC.
  let pt = buildPaEncTsEnc(t)
  let cipher = krbRc4.rc4HmacEncrypt(baseKey, pt, usage = 1)
  result = buildEncryptedData(krbRc4.EtypeRc4Hmac, cipher)

proc buildPaEncTimestampAes*(baseKey: openArray[byte]; etype: uint32;
                             t: Time): seq[byte] =
  ## PA-DATA value for PA-ENC-TIMESTAMP under AES-CTS-HMAC-SHA1-96
  ## (etype 17 or 18). ``baseKey`` is the user's long-term AES key
  ## (i.e., stringToKey output).
  doAssert etype == EtypeAes128 or etype == EtypeAes256
  let pt = buildPaEncTsEnc(t)
  let cipher = krbAes.aesEncrypt(baseKey, pt, usage = 1'u32)
  result = buildEncryptedData(etype, cipher)
