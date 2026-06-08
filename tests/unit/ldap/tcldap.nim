import std/[unittest, strutils]
import msrpc/ldap/cldap
import msrpc/ldap/[messages, ber]

proc hex(d: openArray[byte]): string =
  for b in d: result.add toHex(int(b), 2).toLowerAscii

suite "cldap netlogon query":
  test "buildNetlogonQuery includes the NtVer filter":
    let q = buildNetlogonQuery("example.com", "", "")
    let h = hex(q)
    # NtVer attribute as octet-string: 044e7456 6572 ("NtVer")
    check "04054e74566572" in h
    # filter value 0x06000000 follows (the NtVer flags asking for ResponseEx)
    check "040406000000" in h
    # DnsDomain attribute
    check ("044944" & "6e73446f6d61696e").replace("4944","09")  in h or
          "09446e73446f6d61696e" in h     # length 09 = 9 chars
    # baseObject = "" (rootDSE) — start of search has empty DN.
    check h.startsWith("30")

  test "buildNetlogonQuery is wrapped as a SearchRequest":
    let q = buildNetlogonQuery("", "", "")
    # SEQUENCE { msgID(02 01 01) [APP 3] ... }
    let h = hex(q)
    check "020101" in h
    check "63" in h    # 0x63 = appConstructed(3) = SearchRequest

suite "netlogon response parser":
  test "parses minimal NETLOGON_SAM_LOGON_RESPONSE_EX":
    # Build a synthetic response:
    #   opcode=23 (0x17 0x00)
    #   sbz=0
    #   flags=0x000003fd  (PDC+Gc+Ldap+Ds+Kdc+Timeserv+Closest+Writable+GoodTimeserv)
    #     bits 0,2,3,4,5,6,7,8,9 → 0x3fd
    #   domainGuid: 16 bytes (1..16)
    #   DnsForest: "example.com"
    #   DnsDomain: "example.com" (pointer to forest)
    #   DnsHostname: "dc1.example.com"
    #   netbios domain: "EXAMPLE"
    #   netbios hostname: "DC1"
    #   user name: ""
    #   site name: "Default-First-Site-Name"
    #   client site: "Default-First-Site-Name"
    #   version=5, lmNtToken=0xFFFF, lm20Token=0xFFFF
    var b: seq[byte] = @[]
    b.add @[0x17'u8, 0x00, 0x00, 0x00]
    b.add @[0xfd'u8, 0x03, 0x00, 0x00]
    for i in 1 .. 16: b.add byte(i)
    # DnsForest: example.com
    b.add byte(7)
    for ch in "example": b.add byte(ch.ord)
    b.add byte(3)
    for ch in "com": b.add byte(ch.ord)
    b.add 0'u8                       # end of forest
    let forestOff = 8 + 16            # offset where "example.com" starts
    # DnsDomain: pointer to forest
    b.add byte(0xC0)
    b.add byte(forestOff)
    # DnsHostname: dc1 + pointer to forest
    b.add byte(3)
    for ch in "dc1": b.add byte(ch.ord)
    b.add byte(0xC0); b.add byte(forestOff)
    # NetBIOS domain "EXAMPLE\0"
    b.add byte(7)
    for ch in "EXAMPLE": b.add byte(ch.ord)
    b.add 0'u8
    # NetBIOS hostname "DC1\0"
    b.add byte(3)
    for ch in "DC1": b.add byte(ch.ord)
    b.add 0'u8
    # User name: empty
    b.add 0'u8
    # Site name
    b.add byte(23)
    for ch in "Default-First-Site-Name": b.add byte(ch.ord)
    b.add 0'u8
    # Client site
    b.add byte(23)
    for ch in "Default-First-Site-Name": b.add byte(ch.ord)
    b.add 0'u8
    # version + tokens
    b.add @[5'u8, 0, 0, 0]
    b.add @[0xff'u8, 0xff, 0xff, 0xff]

    let r = parseNetlogonResponse(b)
    check r.opcode == 0x0017
    check flagPdc in r.flags
    check flagKdc in r.flags
    check flagWritable in r.flags
    check r.domainGuid[0] == 1 and r.domainGuid[15] == 16
    check r.dnsForest == "example.com"
    check r.dnsDomain == "example.com"
    check r.dnsHostname == "dc1.example.com"
    check r.netbiosDomain == "EXAMPLE"
    check r.netbiosHostname == "DC1"
    check r.dcSiteName == "Default-First-Site-Name"
    check r.version == 5
