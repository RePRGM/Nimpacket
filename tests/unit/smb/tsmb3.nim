## SMB3 unit tests. Verify key-derivation produces deterministic
## output for known inputs, round-trip encrypt/decrypt over the
## transform header, and that tamper attempts fail.

import std/[unittest, strutils]
import msrpc/common/buffers
import msrpc/smb/smb3
import msrpc/crypto/aes_cmac

proc hex(d: openArray[byte]): string =
  for b in d: result.add toHex(int(b), 2).toLowerAscii

proc unhex(s: string): seq[byte] =
  var t = ""
  for c in s:
    if c != ' ': t.add c
  for i in countup(0, t.len - 1, 2):
    result.add byte(parseHexInt(t[i ..< i+2]))

suite "smb3 key derivation":
  test "derive30Keys produces four 16-byte keys":
    let sk = unhex("000102030405060708090a0b0c0d0e0f")
    let k = derive30Keys(sk)
    check k.signing.len == 16
    check k.encrypt.len == 16
    check k.decrypt.len == 16
    check k.appKey.len  == 16
    check k.signing != k.encrypt
    check k.encrypt != k.decrypt
    # Deterministic
    let k2 = derive30Keys(sk)
    check k.signing == k2.signing

  test "derive311Keys uses preauth hash":
    let sk = unhex("000102030405060708090a0b0c0d0e0f")
    var pa = newSeq[byte](64)
    for i in 0 ..< 64: pa[i] = byte(i)
    let k = derive311Keys(sk, pa)
    check k.signing.len == 16
    # Different preauth hash → different keys
    pa[0] = 0xff
    let k2 = derive311Keys(sk, pa)
    check k.signing != k2.signing

suite "smb3 signing (AES-CMAC)":
  test "signMessage matches aesCmac128 of input":
    let key = unhex("2b7e151628aed2a6abf7158809cf4f3c")
    let msg = unhex("6bc1bee22e409f96e93d7e117393172a")
    check signMessage(key, msg) == aesCmac128(key, msg)

suite "smb3 encryption round-trip":
  test "encrypt then decrypt recovers the plaintext":
    let key = unhex("0001020304050607" & "08090a0b0c0d0e0f")
    let nonce = unhex("aabbccddeeff" & "0102030405")    # 11 bytes
    let sid: uint64 = 0xCAFEBABE_DEADBEEF'u64
    let pt = cast[seq[byte]](@"hello SMB3 transform header world")
    let (th, ct) = encryptPdu(key, pt, nonce, sid)
    check th.len == TransformHeaderLen
    check ct.len == pt.len      # CCM produces same-length ciphertext

    let (pt2, ok) = decryptPdu(key, th, ct)
    check ok
    check pt2 == pt

  test "tampered ciphertext fails verification":
    let key = unhex("00" .repeat(16))
    let nonce = unhex("00" .repeat(11))
    let pt = cast[seq[byte]](@"secret payload")
    let (th, ct) = encryptPdu(key, pt, nonce, 1'u64)
    var ctBad = ct
    ctBad[0] = ctBad[0] xor 1
    let (pt2, ok) = decryptPdu(key, th, ctBad)
    check (not ok)
    check pt2.len == 0

  test "tampered transform header (sessionId) fails":
    let key = unhex("00" .repeat(16))
    let nonce = unhex("00" .repeat(11))
    let pt = cast[seq[byte]](@"another secret")
    var (th, ct) = encryptPdu(key, pt, nonce, 1'u64)
    th[40] = th[40] xor 0xff         # mutate sessionId byte
    let (pt2, ok) = decryptPdu(key, th, ct)
    check (not ok)

suite "smb3 negotiate context layout":
  test "PreauthIntegrity context layout":
    let ctx = buildPreauthIntegrityContext(
      hashAlgs = [HashSha512], salt = @[0x11'u8, 0x22, 0x33])
    # HashAlgorithmCount(2) + SaltLength(2) + Hash(2) + Salt(3) = 9
    check ctx.len == 9
    check ctx[0..1] == @[1'u8, 0]
    check ctx[2..3] == @[3'u8, 0]
    check ctx[4..5] == @[1'u8, 0]
    check ctx[6..8] == @[0x11'u8, 0x22, 0x33]

  test "Encryption context layout":
    let ctx = buildEncryptionContext(@[AesCcm128, AesGcm128])
    check ctx.len == 6
    check ctx[0..1] == @[2'u8, 0]      # count
    check ctx[2..3] == @[1'u8, 0]      # CCM
    check ctx[4..5] == @[2'u8, 0]      # GCM
