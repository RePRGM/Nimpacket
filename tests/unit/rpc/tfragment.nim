import std/unittest
import msrpc/common/buffers
import msrpc/rpc/[pdu, request, fragment]

suite "rpc fragmentation":
  test "small stub fits in one fragment":
    let r = RequestPdu(callId: 1, contextId: 0, opnum: 1,
                       stub: @[1'u8, 2, 3])
    let frags = fragmentRequest(r, maxFrag = 5840)
    check frags.len == 1

  test "stub spans multiple fragments":
    # 100-byte stub with maxFrag = HeaderHdr+overhead+10 → 10 bytes per frag
    let big = block:
      var s = newSeq[byte](100)
      for i in 0 ..< 100: s[i] = byte(i)
      s
    let r = RequestPdu(callId: 9, contextId: 0, opnum: 1, stub: big)
    let chunkSize = 10
    let maxFrag = RequestHeaderOverhead + chunkSize
    let frags = fragmentRequest(r, maxFrag)
    check frags.len == 10

    # Check fragment flags: first has FIRST_FRAG only, last has LAST_FRAG,
    # middle ones have neither.
    var firstHdr = newBuffer(frags[0]).readHeader()
    check pfcFirstFrag in firstHdr.flags
    check pfcLastFrag notin firstHdr.flags

    var midHdr = newBuffer(frags[5]).readHeader()
    check pfcFirstFrag notin midHdr.flags
    check pfcLastFrag  notin midHdr.flags

    var lastHdr = newBuffer(frags[^1]).readHeader()
    check pfcFirstFrag notin lastHdr.flags
    check pfcLastFrag  in lastHdr.flags

    # Reassemble the stubs and verify byte-identical to source.
    var assembled: seq[byte]
    for f in frags:
      let parsed = parseRequest(f)
      assembled.add parsed.stub
    check assembled == big

  test "reassembler combines response fragments":
    let r = newReassembler(callId = 42)
    # Build two response PDUs by hand.
    let r1 = ResponsePdu(callId: 42, contextId: 0, cancelCount: 0,
                         stub: @[1'u8, 2, 3])
    let r2 = ResponsePdu(callId: 42, contextId: 0, cancelCount: 0,
                         stub: @[4'u8, 5, 6, 7])
    let f1 = buildResponse(r1, {pfcFirstFrag})
    let f2 = buildResponse(r2, {pfcLastFrag})
    check (not r.feed(f1))   # not done yet
    check r.feed(f2)         # done
    check r.stub == @[1'u8, 2, 3, 4, 5, 6, 7]
    check r.error == ""

  test "reassembler reports fault":
    let r = newReassembler(callId = 5)
    let f = FaultPdu(callId: 5, contextId: 0, status: 0xC0000022'u32)
    check r.feed(buildFault(f))
    check r.done
    check r.error.len > 0
