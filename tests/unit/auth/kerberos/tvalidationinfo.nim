## KERB_VALIDATION_INFO (PAC logon info) decode tests.
##
## Golden blob built with impacket (KERB_VALIDATION_INFO wrapped in the
## TypeSerialization1 VALIDATION_INFO) for a known user:
##   EffectiveName    : "alice"          UserId (RID)     : 1107
##   LogonDomainName  : "CORP"           PrimaryGroupId   : 513
##   LogonCount       : 3                Groups (RID,attr): (513,7)(512,7)(572,7)
##   LogonDomainId    : S-1-5-21-111-222-333
## Field order and the deferred-referent layout were verified against an
## offset dump of this exact blob.

import std/[unittest, strutils]
import msrpc/auth/kerberos/validationinfo
import msrpc/common/sid

const goldenHex =
  "01100800cccccccc88010000cccccccc0dbe00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000a000a0014b700000000000079450000000000006027000000000000266b0000000000003aaa000000000000a8da000003000000530400000102000003000000652e0000000000000000000000000000000000000000000000000000bc26000008000800feca00004ac1000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000005000000000000000500000061006c00690063006500abab00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003000000010200000700000000020000070000003c0200000700000000000000000000000000000004000000000000000400000043004f0052005000040000000104000000000005150000006f000000de0000004d010000"

proc fromHex(s: string): seq[byte] =
  doAssert s.len mod 2 == 0, "odd hex length " & $s.len
  result = newSeq[byte](s.len div 2)
  for i in 0 ..< result.len:
    result[i] = byte(parseHexInt(s[2*i .. 2*i+1]))

let golden = fromHex(goldenHex)

suite "KERB_VALIDATION_INFO decode":
  let vi = parseValidationInfo(golden)

  test "user and primary group RIDs":
    check vi.userId == 1107
    check vi.primaryGroupId == 513
    check vi.logonCount == 3

  test "account and domain names":
    check vi.effectiveName == "alice"
    check vi.logonDomainName == "CORP"
    check vi.fullName == ""
    check vi.logonServer == ""

  test "group membership list":
    check vi.groups.len == 3
    check vi.groups[0] == GroupMembership(relativeId: 513, attributes: 7)
    check vi.groups[1] == GroupMembership(relativeId: 512, attributes: 7)
    check vi.groups[2] == GroupMembership(relativeId: 572, attributes: 7)

  test "logon-domain SID":
    check vi.hasLogonDomainId
    check $vi.logonDomainId == "S-1-5-21-111-222-333"

  test "no extra SIDs in this PAC":
    check vi.sidCount == 0
    check vi.extraSids.len == 0
    check vi.resourceGroups.len == 0

const goldenExtraSidsHex =
  "01100800ccccccccbc010000ccccccccf67300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000a000a0007330000000000001e3f00000000000092e600000000000094f0000000000000412b00000000000049ad000003000000530400000102000001000000d01a0000200000000000000000000000000000000000000000000000d9860000080008009e8c0000836c00000000000000000000100200000000000000000000000000000000000000000000000000000000000002000000fbe1000000000000000000000000000005000000000000000500000061006c00690063006500abab00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001000000010200000700000000000000000000000000000004000000000000000400000043004f0052005000040000000104000000000005150000006f000000de0000004d010000020000003a620000070000008d85000004000000050000000105000000000005150000006f000000de0000004d0100005704000001000000010100000000001201000000"

suite "KERB_VALIDATION_INFO with ExtraSids":
  let vi = parseValidationInfo(fromHex(goldenExtraSidsHex))

  test "core fields still decode with the longer tail":
    check vi.userId == 1107
    check vi.effectiveName == "alice"
    check vi.logonDomainName == "CORP"
    check vi.groups == @[GroupMembership(relativeId: 513, attributes: 7)]
    check $vi.logonDomainId == "S-1-5-21-111-222-333"
    check vi.userFlags == 0x20
    check vi.userAccountControl == 0x210

  test "extra SIDs (SID history) decode with attributes":
    check vi.sidCount == 2
    check vi.extraSids.len == 2
    check $vi.extraSids[0].sid == "S-1-5-21-111-222-333-1111"
    check vi.extraSids[0].attributes == 7
    check $vi.extraSids[1].sid == "S-1-18-1"
    check vi.extraSids[1].attributes == 4

  test "no resource groups in this PAC":
    check vi.resourceGroups.len == 0
    check vi.hasResourceGroupDomainSid == false

suite "KERB_VALIDATION_INFO rejects bad input":
  test "wrong type-serialization header":
    var bad = golden
    bad[0] = 2
    expect PacDecodeError:
      discard parseValidationInfo(bad)

  test "truncated blob is rejected, not crashed":
    expect PacDecodeError:
      discard parseValidationInfo(golden[0 ..< 60])
