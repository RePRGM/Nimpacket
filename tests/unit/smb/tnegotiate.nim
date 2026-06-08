import std/[unittest, strutils]
import msrpc/smb/[client, smb3]

proc hex(d: openArray[byte]): string =
  for b in d: result.add toHex(int(b), 2).toLowerAscii

suite "SMB NEGOTIATE body":
  test "2.0.2 only body has no contexts":
    let body = buildNegotiateBody([Smb202])
    # StructureSize=36, DialectCount=1, dialect 0x0202 appears at offset 36
    check body.len == 40              # 36 + 1 dialect (2 bytes) + 2 pad
    check body[0] == 0x24'u8          # StructureSize LE low byte
    check body[2] == 1'u8             # DialectCount = 1
    # Last 4 bytes: dialect + pad
    check "02020000" in hex(body)

  test "3.0/3.0.2 body sets ENCRYPTION capability bit":
    let body = buildNegotiateBody([Smb300, Smb302])
    # Capabilities at offset 8 (LE): LARGE_MTU 0x04 | ENCRYPTION 0x40 = 0x44
    check body[8] == 0x44'u8

  test "3.1.1 offer appends two negotiate contexts":
    let body = buildNegotiateBody([Smb202, Smb210, Smb300, Smb302, Smb311])
    # NegotiateContextOffset (4 bytes at body offset 28) must point past
    # the padded dialect list. 5 dialects = 10 bytes; prefixLen = 36 + 10
    # = 46; padded to 48; ctxStartFromHeader = 64 + 48 = 112.
    let off =
      uint32(body[28]) or
      (uint32(body[29]) shl 8) or
      (uint32(body[30]) shl 16) or
      (uint32(body[31]) shl 24)
    check off == 112'u32
    # NegotiateContextCount at offset 32 = 2
    check body[32] == 2'u8
    # CtxPreauthIntegrity (0x0001) and CtxEncryption (0x0002) appear
    # in the trailing context bytes.
    let tail = hex(body[48 ..< body.len])
    check "0100" in tail               # preauth context type LE
    check "0200" in tail               # encryption context type LE
    # SHA-512 hash algorithm 0x0001
    check "0100" in tail
    # AES-CCM-128 cipher 0x0001
    check tail.len >= 80               # both contexts + padding
