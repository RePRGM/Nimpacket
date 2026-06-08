## RFC 4121 GSS_Wrap / GSS_GetMIC round-trip tests.

import std/[unittest, strutils]
import msrpc/auth/kerberos/[etype, gsswrap]

proc str(s: string): seq[byte] =
  result = newSeq[byte](s.len)
  for i, c in s: result[i] = byte(c)

proc makeKey(etype: uint32): seq[byte] =
  ## Reproducible session key per ETYPE — RFC 3962 vector for "password"
  ## with the standard salt at 1200 iterations.
  stringToKey(str("password"), str("ATHENA.MIT.EDUraeburn"),
              etype, iterations = 1200)

suite "Kerberos GSS Wrap (sealed)":
  test "AES-128: client→server round-trip recovers plaintext":
    let key = makeKey(EtypeAes128)
    let plain = str("hello, kerberos world")
    let token = gssWrap(key, plain, sndSeq = 0'u64, isInitiator = true)
    # Token layout: 16 bytes header + (plain.len + 16 confounder + 16
    # trailing-header + 12 hmac) = 60 bytes overhead.
    check token.len == 16 + plain.len + 16 + 16 + 12
    # Receiver-side (acceptor) unwrap: it's "us" the initiator that
    # called Wrap, so the acceptor side sees isInitiator=false.
    let (rec, sndSeq, ok) = gssUnwrap(key, token, isInitiator = false)
    check ok
    check sndSeq == 0'u64
    check rec == plain

  test "AES-256: server→client round-trip recovers plaintext":
    let key = makeKey(EtypeAes256)
    let plain = str("server says hi")
    let token = gssWrap(key, plain, sndSeq = 42'u64, isInitiator = false)
    let (rec, sndSeq, ok) = gssUnwrap(key, token, isInitiator = true)
    check ok
    check sndSeq == 42'u64
    check rec == plain

  test "tampering with the encrypted body fails verification":
    let key = makeKey(EtypeAes128)
    var token = gssWrap(key, str("attack at dawn"), 1'u64, isInitiator = true)
    token[20] = token[20] xor 0x01      # flip a bit deep in the cipher
    let (_, _, ok) = gssUnwrap(key, token, isInitiator = false)
    check not ok

  test "tampering with the cleartext token header fails":
    let key = makeKey(EtypeAes128)
    var token = gssWrap(key, str("retreat at dusk"), 2'u64, isInitiator = true)
    token[2] = token[2] xor FlagSealed   # flip the Sealed bit in plaintext
    let (_, _, ok) = gssUnwrap(key, token, isInitiator = false)
    check not ok

  test "direction mismatch is rejected":
    let key = makeKey(EtypeAes128)
    let token = gssWrap(key, str("client to server"), 3'u64,
                         isInitiator = true)
    # Try to unwrap as if we were the initiator (i.e., expect the peer
    # to be the acceptor). The token was sent by the initiator → reject.
    let (_, _, ok) = gssUnwrap(key, token, isInitiator = true)
    check not ok

  test "sequence numbers are big-endian and decode correctly":
    let key = makeKey(EtypeAes128)
    let token = gssWrap(key, str("seq test"),
                         sndSeq = 0x0123456789ABCDEF'u64,
                         isInitiator = true)
    # Bytes 8..15 of the header should be the seq in BE.
    check token[8]  == 0x01'u8
    check token[9]  == 0x23'u8
    check token[15] == 0xEF'u8
    let (_, sndSeq, ok) = gssUnwrap(key, token, isInitiator = false)
    check ok
    check sndSeq == 0x0123456789ABCDEF'u64

suite "Kerberos GSS MIC (integrity only)":
  test "AES-256 MIC round-trip verifies":
    let key = makeKey(EtypeAes256)
    let msg = str("just sign this, don't encrypt")
    let mic = gssGetMic(key, msg, sndSeq = 7'u64, isInitiator = true)
    check mic.len == TokenHeaderLen + 12
    let (sndSeq, ok) = gssVerifyMic(key, msg, mic, isInitiator = false)
    check ok
    check sndSeq == 7'u64

  test "MIC catches body tampering":
    let key = makeKey(EtypeAes128)
    let msg = str("original message")
    let mic = gssGetMic(key, msg, sndSeq = 0'u64, isInitiator = true)
    let tampered = str("modified message")
    let (_, ok) = gssVerifyMic(key, tampered, mic, isInitiator = false)
    check not ok

  test "MIC catches MIC-bit tampering":
    let key = makeKey(EtypeAes128)
    let msg = str("message")
    var mic = gssGetMic(key, msg, sndSeq = 0'u64, isInitiator = true)
    mic[mic.len - 1] = mic[mic.len - 1] xor 0x01
    let (_, ok) = gssVerifyMic(key, msg, mic, isInitiator = false)
    check not ok
