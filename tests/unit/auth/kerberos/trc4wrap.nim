## RFC 4757 §7.3 RC4-HMAC GSS Wrap and MIC round-trip + tamper tests.

import std/[unittest, strutils]
import msrpc/auth/kerberos/rc4wrap

proc str(s: string): seq[byte] =
  result = newSeq[byte](s.len)
  for i, c in s: result[i] = byte(c)

proc makeKey(): seq[byte] =
  ## A reproducible 16-byte session key. Real callers would use the
  ## TGS session key (already 16 bytes for RC4-HMAC).
  result = newSeq[byte](16)
  for i in 0 ..< 16: result[i] = byte(0x80 - i)

suite "RC4-HMAC GSS Wrap (RFC 4757 §7.3)":
  test "token is 32 bytes and body is encrypted in place":
    let key = makeKey()
    var body = str("body that gets encrypted in place")
    let original = body
    let token = rc4WrapSeal(key, body, body.len, seq = 0'u32,
                             isInitiator = true)
    check token.len == 32
    check token[0] == 0x02'u8 and token[1] == 0x01'u8  # TOK_ID = Wrap
    check token[4] == 0x10'u8 and token[5] == 0x00'u8  # SEAL_ALG = RC4
    check body.len == original.len
    check body != original

  test "client→server round-trip recovers plaintext":
    let key = makeKey()
    let original = str("hello RC4-HMAC over GSS Wrap")
    var body = original
    let token = rc4WrapSeal(key, body, body.len, seq = 1'u32,
                             isInitiator = true)
    let (gotSeq, ok) = rc4WrapUnseal(key, body, body.len, token,
                                     isInitiator = false)
    check ok
    check gotSeq == 1'u32
    check body == original

  test "server→client round-trip recovers plaintext":
    let key = makeKey()
    let original = str("server reply across the wire")
    var body = original
    let token = rc4WrapSeal(key, body, body.len, seq = 99'u32,
                             isInitiator = false)
    let (gotSeq, ok) = rc4WrapUnseal(key, body, body.len, token,
                                     isInitiator = true)
    check ok
    check gotSeq == 99'u32
    check body == original

  test "tampering with the ciphertext breaks checksum":
    let key = makeKey()
    var body = str("legitimate body")
    let token = rc4WrapSeal(key, body, body.len, seq = 0'u32,
                             isInitiator = true)
    body[3] = body[3] xor 0x01
    let (_, ok) = rc4WrapUnseal(key, body, body.len, token,
                                isInitiator = false)
    check not ok

  test "tampering with the token's checksum bytes fails":
    let key = makeKey()
    var body = str("legitimate body")
    var token = rc4WrapSeal(key, body, body.len, seq = 0'u32,
                             isInitiator = true)
    token[16] = token[16] xor 0x80    # flip a bit in SGN_CKSUM
    let (_, ok) = rc4WrapUnseal(key, body, body.len, token,
                                isInitiator = false)
    check not ok

  test "direction marker mismatch is rejected":
    let key = makeKey()
    var body = str("from client direction")
    let token = rc4WrapSeal(key, body, body.len, seq = 0'u32,
                             isInitiator = true)
    # Pretend we're the initiator unwrapping — but the token was also
    # from the initiator, so direction polarity should fail.
    let (_, ok) = rc4WrapUnseal(key, body, body.len, token,
                                isInitiator = true)
    check not ok

  test "sequence number is recovered correctly":
    let key = makeKey()
    var body = str("seq check")
    let token = rc4WrapSeal(key, body, body.len, seq = 0xDEADBEEF'u32,
                             isInitiator = true)
    let (gotSeq, ok) = rc4WrapUnseal(key, body, body.len, token,
                                     isInitiator = false)
    check ok
    check gotSeq == 0xDEADBEEF'u32

suite "RC4-HMAC GSS MIC (integrity-only)":
  test "MIC round-trip verifies":
    let key = makeKey()
    let msg = str("sign me, don't seal me")
    let mic = rc4GetMic(key, msg, seq = 5'u32, isInitiator = true)
    check mic.len == 32
    check mic[0] == 0x01'u8 and mic[1] == 0x01'u8       # TOK_ID = MIC
    check mic[4] == 0xFF'u8 and mic[5] == 0xFF'u8       # SEAL_ALG = none
    let (gotSeq, ok) = rc4VerifyMic(key, msg, mic, isInitiator = false)
    check ok
    check gotSeq == 5'u32

  test "MIC catches message tampering":
    let key = makeKey()
    let mic = rc4GetMic(key, str("original message"),
                        seq = 0'u32, isInitiator = true)
    let (_, ok) = rc4VerifyMic(key, str("modified message"),
                               mic, isInitiator = false)
    check not ok

  test "MIC catches checksum tampering":
    let key = makeKey()
    var mic = rc4GetMic(key, str("message"),
                        seq = 0'u32, isInitiator = true)
    mic[20] = mic[20] xor 0x40
    let (_, ok) = rc4VerifyMic(key, str("message"), mic,
                               isInitiator = false)
    check not ok
