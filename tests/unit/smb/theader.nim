import std/unittest
import msrpc/common/buffers
import msrpc/smb/header

suite "smb2 header":
  test "round-trip":
    let h = Smb2Header(
      creditCharge: 1, status: 0,
      command: cmdNegotiate,
      creditsRequested: 64,
      flags: 0, nextCommand: 0,
      messageId: 0, treeId: 0, sessionId: 0)
    let b = newBuffer()
    b.writeHeader(h)
    check b.consumed.len == SmbHeaderLen
    # Signature byte
    check b.consumed[0..3] == @SmbSignature
    let r = newBuffer(b.consumed)
    check r.readHeader() == h

  test "command values match SMB2":
    check uint16(ord(cmdNegotiate))     == 0x0000
    check uint16(ord(cmdSessionSetup))  == 0x0001
    check uint16(ord(cmdTreeConnect))   == 0x0003
    check uint16(ord(cmdCreate))        == 0x0005
    check uint16(ord(cmdClose))         == 0x0006
    check uint16(ord(cmdRead))          == 0x0008
    check uint16(ord(cmdWrite))         == 0x0009
