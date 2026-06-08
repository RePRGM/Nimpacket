## Verify the sign/encrypt path produces well-formed output:
##  - signing flips the SMB2_FLAGS_SIGNED bit, zeros bytes 48..63
##    before CMAC, and writes a 16-byte tag back at 48..63
##  - encryption produces a TRANSFORM_HEADER + ciphertext whose
##    decrypt round-trips back to the original plaintext

import std/unittest
import msrpc/smb/[client, smb3, header]
import msrpc/common/[buffers, endian]

proc fakeSession(): SmbSession =
  result = SmbSession(messageId: 0, treeId: 0, sessionId: 0xCAFEBABE'u64)
  result.signingKey = newSeq[byte](16)
  result.encryptKey = newSeq[byte](16)
  for i in 0 ..< 16:
    result.signingKey[i] = byte(i + 1)
    result.encryptKey[i] = byte(0x10 + i)
  result.decryptKey = result.encryptKey   # AFTER the fill — seqs copy by value

proc buildSmbHeaderOnly(): seq[byte] =
  let h = Smb2Header(
    creditCharge: 1, command: cmdEcho, creditsRequested: 1,
    flags: 0, messageId: 0, treeId: 0, sessionId: 0xCAFEBABE'u64)
  let b = newBuffer()
  b.writeHeader(h)
  # echo body: StructureSize=4 + 2 reserved bytes
  b.writeU16LE(4)
  b.writeU16LE(0)
  result = b.consumed

suite "SMB sign + encrypt path":
  test "signing sets FLAGS_SIGNED and writes a non-zero tag":
    let s = fakeSession()
    s.signingActive = true
    let pkt = buildSmbHeaderOnly()
    let signed = maybeSignOrEncrypt(s, pkt)
    # SMB2 flags field starts at offset 16 (4 magic + 2 structsize +
    # 2 creditCharge + 4 status + 2 cmd + 2 credits = 16). Low byte of
    # flags carries the SIGNED bit (0x08).
    check (signed[16] and 0x08'u8) != 0
    # Signature bytes 48..63 are not all zero
    var anyNonZero = false
    for i in 48 ..< 64:
      if signed[i] != 0: anyNonZero = true
    check anyNonZero
    # Body bytes (after the 64-byte header) are untouched.
    check signed[64 ..< signed.len] == pkt[64 ..< pkt.len]

  test "encryption emits TRANSFORM_HEADER + ciphertext":
    let s = fakeSession()
    s.encryptionActive = true
    let pkt = buildSmbHeaderOnly()
    let wrapped = maybeSignOrEncrypt(s, pkt)
    check wrapped[0] == 0xFD'u8
    check wrapped[1] == byte('S')
    check wrapped[2] == byte('M')
    check wrapped[3] == byte('B')
    # Total length = TransformHeaderLen + plaintext.len
    check wrapped.len == TransformHeaderLen + pkt.len
    # The ciphertext portion must not equal the plaintext (CCM was applied).
    let ct = wrapped[TransformHeaderLen ..< wrapped.len]
    check ct != pkt

  test "encrypt then decrypt round-trips":
    let s = fakeSession()
    s.encryptionActive = true
    let pkt = buildSmbHeaderOnly()
    let wrapped = maybeSignOrEncrypt(s, pkt)
    let th = wrapped[0 ..< TransformHeaderLen]
    let ct = wrapped[TransformHeaderLen ..< wrapped.len]
    let (pt, ok) = decryptPdu(s.decryptKey, th, ct)
    check ok
    check pt == pkt
