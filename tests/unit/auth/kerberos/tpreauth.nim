import std/[unittest, times]
import msrpc/common/buffers
import msrpc/auth/spnego/asn1
import msrpc/auth/kerberos/[rc4, preauth]

suite "Kerberos EncryptedData":
  test "wrapper has correct ASN.1 tag and contains etype/cipher":
    let cipher = @[0xDE'u8, 0xAD, 0xBE, 0xEF]
    let ed = buildEncryptedData(EtypeRc4Hmac, cipher)
    let b = newBuffer(ed)
    let seqLen = b.derReadTag(tagSequence)
    discard seqLen
    discard b.derReadTag(ctxConstructed(0))    # [0] etype
    let etypeLen = b.derReadTag(0x02'u8)        # INTEGER
    var et = 0
    for _ in 0 ..< etypeLen: et = (et shl 8) or int(b.readByte())
    check et == int(EtypeRc4Hmac)
    discard b.derReadTag(ctxConstructed(2))    # [2] cipher
    let ctLen = b.derReadTag(tagOctetString)
    let ctBytes = b.readBytes(ctLen)
    check ctBytes == cipher

suite "PA-ENC-TIMESTAMP RC4":
  test "round-trip: build then decrypt yields PA-ENC-TS-ENC plaintext":
    let key = rc4HmacStringToKey("Password")
    let t = fromUnix(1700000000)   # arbitrary fixed moment
    let pa = buildPaEncTimestampRc4(key, t)
    # Parse the EncryptedData and pull the cipher out.
    let b = newBuffer(pa)
    discard b.derReadTag(tagSequence)
    discard b.derReadTag(ctxConstructed(0))
    let etLen = b.derReadTag(0x02'u8)
    var et = 0
    for _ in 0 ..< etLen: et = (et shl 8) or int(b.readByte())
    check et == int(EtypeRc4Hmac)
    discard b.derReadTag(ctxConstructed(2))
    let cLen = b.derReadTag(tagOctetString)
    let cipher = b.readBytes(cLen)
    # Decrypt with the user's key + usage = 1
    let (pt, ok) = rc4HmacDecrypt(key, cipher, usage = 1)
    check ok
    # Plaintext should be a PA-ENC-TS-ENC SEQUENCE wrapping a
    # KerberosTime GeneralizedTime (tag 0x18). Just verify the tag.
    check pt[0] == tagSequence
