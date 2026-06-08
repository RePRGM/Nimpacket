## wrapper round-trip: a client provider seals a PDU body and a
## "server" provider (sharing the same ExportedSessionKey) unseals it.

import std/unittest
import msrpc/auth/ntlm/[provider, session]
import msrpc/crypto/rc4
import msrpc/rpc/[pdu, auth, wrapper]

proc cloneAsServer(c: NtlmProvider): NtlmProvider =
  ## Build a peer provider with a session whose server-direction keys
  ## match the client's client-direction keys.
  result = newNtlmProvider("D", "U", "P")
  result.session = newNtlmSession(c.exportedSessionKey)
  # Reverse the perspective: from the server's point of view, the
  # bytes it "receives" are signed with the CLIENT signing/sealing key.
  result.session.serverSigningKey = c.session.clientSigningKey
  result.session.serverSealingKey = c.session.clientSealingKey
  result.session.serverSeal = c.session.clientSeal       # state snapshot
  # Reset the state because the act of cloning advances nothing; we
  # need a fresh RC4 keyed from the same key.
  result.session.serverSeal.initRc4(c.session.clientSealingKey)

proc primedProvider(): NtlmProvider =
  ## Build a provider with a known ExportedSessionKey (skips the real
  ## handshake; we only care about the wrap/unwrap path).
  result = newNtlmProvider("D", "U", "P")
  for i in 0 ..< 16: result.exportedSessionKey[i] = 0x55'u8
  result.session = newNtlmSession(result.exportedSessionKey)

suite "rpc wrapper":
  test "privacy: wrap then unwrap reproduces stub":
    let client = primedProvider()
    let server = cloneAsServer(client)

    let stub = @[0xCA'u8, 0xFE, 0xBA, 0xBE, 0x01, 0x02, 0x03]
    # REQUEST prologue: alloc_hint(4) + p_cont_id(2) + opnum(2) = 8 bytes
    let prologue = @[byte(stub.len), 0, 0, 0,   # alloc_hint
                     0, 0,                       # p_cont_id
                     1, 0]                       # opnum
    var hdr = defaultHeader(ptRequest, callId = 1)
    let wrapped = wrapOutgoing(hdr, stub, client,
                                level = alPktPrivacy,
                                contextId = 0,
                                typeSpecificPrologue = prologue)
    check wrapped.len > HeaderLen + stub.len   # padding + trailer + verifier

    let (gotStub, ok) = unwrapIncoming(wrapped, server, prologueLen = 8)
    check ok
    check gotStub == stub

  test "padding aligns to 4 bytes":
    let client = primedProvider()
    let server = cloneAsServer(client)
    # Stub length 7, prologue 8: total = 15, pad to 16 = pad_length 1.
    let stub = @[1'u8, 2, 3, 4, 5, 6, 7]
    let prologue = @[7'u8, 0, 0, 0, 0, 0, 1, 0]
    var hdr = defaultHeader(ptRequest, callId = 7)
    let wrapped = wrapOutgoing(hdr, stub, client,
                                level = alPktPrivacy,
                                contextId = 0,
                                typeSpecificPrologue = prologue)
    let (gotStub, ok) = unwrapIncoming(wrapped, server, prologueLen = 8)
    check ok
    check gotStub == stub

  test "tampered ciphertext fails to verify":
    let client = primedProvider()
    let server = cloneAsServer(client)

    let stub = @[0xAA'u8, 0xBB, 0xCC, 0xDD]
    let prologue = @[4'u8, 0, 0, 0, 0, 0, 0, 0]
    var hdr = defaultHeader(ptRequest, callId = 2)
    var wrapped = wrapOutgoing(hdr, stub, client,
                                level = alPktPrivacy,
                                contextId = 0,
                                typeSpecificPrologue = prologue)
    # Flip a byte in the stub-cipher area.
    wrapped[HeaderLen + 8] = wrapped[HeaderLen + 8] xor 0x01
    let (_, ok) = unwrapIncoming(wrapped, server, prologueLen = 8)
    check not ok
