## MS-KILE §3.4.5.4.1 GSS_WrapEx round-trip + tamper detection tests.
##
## These are loopback only — we don't have a Microsoft target to verify
## byte compatibility against, so any "is this MS-RPC wire-compatible?"
## claim still needs a packet capture. What we verify here is that the
## crypto math is internally consistent and matches RFC 4121 §4.2.

import std/[unittest, strutils]
import msrpc/auth/kerberos/[etype, wrapex]

proc str(s: string): seq[byte] =
  result = newSeq[byte](s.len)
  for i, c in s: result[i] = byte(c)

proc makeKey(etype: uint32): seq[byte] =
  stringToKey(str("password"), str("ATHENA.MIT.EDUraeburn"),
              etype, iterations = 1200)

suite "MS-KILE GSS_WrapEx (AES-CTS-HMAC-SHA1-96)":
  test "verifier is exactly 60 bytes (Header 32 + Trailer 28)":
    let key = makeKey(EtypeAes128)
    var body = str("twenty four byte body!!!")
    check body.len == 24
    let verifier = wrapExEncrypt(key, body, body.len, sndSeq = 0, isInitiator = true)
    check verifier.len == WrapExVerifierLen
    check WrapExVerifierLen == 60

  test "body is encrypted in place (same length as plaintext)":
    let key = makeKey(EtypeAes128)
    let original = str("body bytes that get encrypted")
    var body = original
    discard wrapExEncrypt(key, body, body.len, sndSeq = 0, isInitiator = true)
    check body.len == original.len
    check body != original                # actually encrypted

  test "AES-128 client→server round-trip recovers plaintext":
    let key = makeKey(EtypeAes128)
    let original = str("hello over wrapex from client")
    var body = original
    let verifier = wrapExEncrypt(key, body, body.len, sndSeq = 1, isInitiator = true)
    var bodyCopy = body                   # still encrypted in this seq
    let (gotSeq, ok) = wrapExDecrypt(key, bodyCopy, bodyCopy.len, verifier,
                                     isInitiator = false)
    check ok
    check gotSeq == 1'u64
    check bodyCopy == original

  test "AES-256 server→client round-trip recovers plaintext":
    let key = makeKey(EtypeAes256)
    let original = str("64-byte body: " &
                       "padded out to confirm multi-block CTS handling.....")
    var body = original
    let verifier = wrapExEncrypt(key, body, body.len,
                                 sndSeq = 0xCAFE'u64,
                                 isInitiator = false)
    var bodyCopy = body
    let (gotSeq, ok) = wrapExDecrypt(key, bodyCopy, bodyCopy.len, verifier,
                                     isInitiator = true)
    check ok
    check gotSeq == 0xCAFE'u64
    check bodyCopy == original

  test "tampering with encrypted body fails verification":
    let key = makeKey(EtypeAes128)
    var body = str("legitimate request body")
    let verifier = wrapExEncrypt(key, body, body.len, sndSeq = 0, isInitiator = true)
    body[5] = body[5] xor 0x01            # flip a bit
    var bodyCopy = body
    let (_, ok) = wrapExDecrypt(key, bodyCopy, bodyCopy.len, verifier,
                                isInitiator = false)
    check not ok

  test "tampering with cleartext token header fails verification":
    let key = makeKey(EtypeAes128)
    var body = str("body unchanged")
    var verifier = wrapExEncrypt(key, body, body.len, sndSeq = 0, isInitiator = true)
    verifier[2] = verifier[2] xor 0x02    # flip the Sealed flag bit
    var bodyCopy = body
    let (_, ok) = wrapExDecrypt(key, bodyCopy, bodyCopy.len, verifier,
                                isInitiator = false)
    check not ok

  test "tampering with the HMAC tag fails verification":
    let key = makeKey(EtypeAes128)
    var body = str("body unchanged")
    var verifier = wrapExEncrypt(key, body, body.len, sndSeq = 0, isInitiator = true)
    verifier[verifier.len - 1] = verifier[verifier.len - 1] xor 0x80
    var bodyCopy = body
    let (_, ok) = wrapExDecrypt(key, bodyCopy, bodyCopy.len, verifier,
                                isInitiator = false)
    check not ok

  test "tampering with the encrypted-confounder bytes fails":
    let key = makeKey(EtypeAes128)
    var body = str("body unchanged")
    var verifier = wrapExEncrypt(key, body, body.len, sndSeq = 0, isInitiator = true)
    # Bytes 16..31 of the verifier are AES-CTS output covering the
    # confounder — tampering here breaks the trail-header check.
    verifier[20] = verifier[20] xor 0x40
    var bodyCopy = body
    let (_, ok) = wrapExDecrypt(key, bodyCopy, bodyCopy.len, verifier,
                                isInitiator = false)
    check not ok

  test "direction mismatch is rejected":
    let key = makeKey(EtypeAes128)
    var body = str("from client")
    let verifier = wrapExEncrypt(key, body, body.len, sndSeq = 0, isInitiator = true)
    # Try to unwrap as if the token were from the acceptor — wrong.
    var bodyCopy = body
    let (_, ok) = wrapExDecrypt(key, bodyCopy, bodyCopy.len, verifier,
                                isInitiator = true)
    check not ok

  test "sequence numbers are big-endian and decode correctly":
    let key = makeKey(EtypeAes128)
    var body = str("seq check")
    let verifier = wrapExEncrypt(key, body, body.len,
                                 sndSeq = 0x0123456789ABCDEF'u64,
                                 isInitiator = true)
    check verifier[8]  == 0x01'u8
    check verifier[9]  == 0x23'u8
    check verifier[15] == 0xEF'u8
    var bodyCopy = body
    let (gotSeq, ok) = wrapExDecrypt(key, bodyCopy, bodyCopy.len, verifier,
                                     isInitiator = false)
    check ok
    check gotSeq == 0x0123456789ABCDEF'u64
