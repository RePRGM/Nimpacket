import std/[unittest, strutils]
import msrpc/rpc/auth as rpcauth
import msrpc/auth/spnego/provider as spnegoprovider

type
  FakeKerberosInner = ref object of AuthProvider
    canned: seq[byte]

method initialize(p: FakeKerberosInner; targetSpn: string): seq[byte] =
  result = p.canned

method step(p: FakeKerberosInner; serverToken: openArray[byte]): seq[byte] =
  result = @[]

proc hex(d: openArray[byte]): string =
  for b in d: result.add toHex(int(b), 2).toLowerAscii

suite "SPNEGO + Kerberos":
  test "initial token contains KRB5 OID":
    # 4 bytes that look like an AP-REQ token. We only care that they
    # end up inside the mechToken of the NegTokenInit.
    let canned = @[0x60'u8, 0x02, 0xAA, 0xBB]
    let fake = FakeKerberosInner(canned: canned)
    fake.state = asContinue
    fake.authLevel = alPktIntegrity
    let sp = newSpnegoKerberos(fake)
    let tok = sp.initialize("cifs/dc.example.com")
    let hs = hex(tok)
    # SPNEGO outer [APP 0] tag
    check tok[0] == 0x60'u8
    # SPNEGO OID 1.3.6.1.5.5.2 → 06 06 2b 06 01 05 05 02
    check "06062b0601050502" in hs
    # KRB5 OID 1.2.840.113554.1.2.2 → 06 09 2a 86 48 86 f7 12 01 02 02
    check "06092a864886f71201" & "0202" in hs
    # mechToken bytes appear verbatim inside the wrap
    check "60" & "02aabb" in hs
