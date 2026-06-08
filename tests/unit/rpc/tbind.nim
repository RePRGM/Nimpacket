import std/unittest
import msrpc/common/[buffers, guid]
import msrpc/rpc/[pdu, binds]

const RaaInterface = "0b1c2170-5732-4e0e-8cd3-d9b16f3b84d7"

proc raaSyntax(): SyntaxId =
  SyntaxId(uuid: parseUuid(RaaInterface), version: 0'u32)

suite "rpc bind":
  test "buildBind then parse round-trip with NDR+NDR64":
    let p = BindPdu(
      maxXmit: 5840, maxRecv: 5840, assocGroupId: 0,
      contexts: @[
        PresentationContext(contextId: 0,
          abstractSyntax: raaSyntax(),
          transferSyntaxes: @[ndrTransferSyntax()]),
        PresentationContext(contextId: 1,
          abstractSyntax: raaSyntax(),
          transferSyntaxes: @[ndr64TransferSyntax()])])
    let bytes = buildBind(callId = 1, p)
    let b = newBuffer(bytes)
    let hdr = b.readHeader()
    check hdr.pType == ptBind
    check hdr.fragLen == uint16(bytes.len)
    let parsed = b.parseBindBody()
    check parsed.contexts.len == 2
    check parsed.contexts[0].contextId == 0
    check parsed.contexts[0].abstractSyntax.uuid == parseUuid(RaaInterface)
    check parsed.contexts[0].transferSyntaxes[0].uuid ==
          parseUuid(NdrTransferUuid)
    check parsed.contexts[1].transferSyntaxes[0].uuid ==
          parseUuid(Ndr64TransferUuid)
    check parsed.maxXmit == 5840
    check parsed.maxRecv == 5840

  test "wire layout: counts and reserved bytes":
    let p = BindPdu(
      maxXmit: 4280, maxRecv: 4280, assocGroupId: 0xAABBCCDD'u32,
      contexts: @[
        PresentationContext(contextId: 7,
          abstractSyntax: raaSyntax(),
          transferSyntaxes: @[ndrTransferSyntax()])])
    let bytes = buildBindBody(p)
    # offset 0..3: maxXmit, maxRecv (LE u16 each)
    check bytes[0..3] == @[0xB8'u8, 0x10, 0xB8, 0x10]
    # offset 4..7: assoc_group_id (LE u32)
    check bytes[4..7] == @[0xDD'u8, 0xCC, 0xBB, 0xAA]
    # offset 8: n_context_elem
    check bytes[8] == 1
    # 9..11 reserved
    check bytes[9..11] == @[0'u8, 0, 0]
    # 12..13 contextId = 7
    check bytes[12..13] == @[7'u8, 0]
    # 14: n_transfer_syn = 1
    check bytes[14] == 1
    # abstract syntax: UUID (16) + version (4) = 20 bytes starting at 16
    let raa = parseUuid(RaaInterface)
    check bytes[16 ..< 32] == raa.toWire()

  test "buildBindAck then parse":
    let p = BindAckPdu(
      maxXmit: 5840, maxRecv: 5840, assocGroupId: 0x42,
      secondaryAddress: "\\PIPE\\test",
      results: @[
        PContextResultEntry(result: pcAcceptance, reason: 0,
                            transferSyntax: ndrTransferSyntax()),
        PContextResultEntry(result: pcProviderRejection, reason: 2,
                            transferSyntax: SyntaxId())])
    let bytes = buildBindAck(callId = 1, p)
    let b = newBuffer(bytes)
    let hdr = b.readHeader()
    check hdr.pType == ptBindAck
    let parsed = b.parseBindAckBody()
    check parsed.secondaryAddress == "\\PIPE\\test"
    check parsed.results.len == 2
    check parsed.results[0].result == pcAcceptance
    check parsed.results[0].transferSyntax.uuid == parseUuid(NdrTransferUuid)
    check parsed.results[1].result == pcProviderRejection
    check parsed.results[1].reason == 2

  test "empty secondary address":
    let p = BindAckPdu(maxXmit: 5840, maxRecv: 5840, assocGroupId: 0,
                       secondaryAddress: "",
                       results: @[
                         PContextResultEntry(result: pcAcceptance,
                                             reason: 0,
                                             transferSyntax: ndrTransferSyntax())])
    let bytes = buildBindAck(0, p)
    let b = newBuffer(bytes)
    discard b.readHeader()
    let parsed = b.parseBindAckBody()
    check parsed.secondaryAddress == ""
    check parsed.results.len == 1
