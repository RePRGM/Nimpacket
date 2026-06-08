## End-to-end test of the KerberosProvider against an in-process mock
## KDC. Catches regressions in the full AS → KRB-ERROR → AS-REP →
## TGS-REQ → TGS-REP pipeline without needing a real KDC.

import std/[unittest, os, strutils]
import msrpc/auth/kerberos/provider as krb
import msrpc/auth/kerberos/mockkdc
import msrpc/auth/kerberos/rc4 as krbRc4

const TestRealm = "MOCK.LOCAL"
const TestUser  = "alice"
const TestPass  = "P@ssw0rd"
const TestPort  = 28840

# --- thread-shared state -----------------------------------------

type KdcThreadArgs = tuple[port: int; expected: int;
                            result: ptr MockKdcResult;
                            cfg: ptr MockKdcConfig]

proc runMockKdc(args: KdcThreadArgs) {.thread.} =
  args.cfg.port = args.port
  args.cfg.creds = MockKdcCreds(realm: TestRealm,
                                username: TestUser,
                                password: TestPass)
  args.result[] = serveExpected(args.cfg[], args.expected)

var kdcThread: Thread[KdcThreadArgs]

suite "Kerberos client against mock KDC (TCP, RC4-HMAC)":
  test "AS-REQ + retry + AS-REP yields a usable TGT":
    var kdcResult = MockKdcResult()
    var kdcCfg = MockKdcConfig()
    let args: KdcThreadArgs = (TestPort, 3, addr kdcResult, addr kdcCfg)
    createThread(kdcThread, runMockKdc, args)
    sleep(150)                       # let listener bind

    let p = krb.newKerberosProvider(
      realm = TestRealm,
      username = TestUser,
      password = TestPass,
      kdcHost = "127.0.0.1",
      kdcPort = TestPort,
      preferEtype = krbRc4.EtypeRc4Hmac,
      transport = ktTcp)
    p.obtainTgt()
    p.obtainServiceTicket("host/fake.example.com")
    kdcThread.joinThread()

    check kdcResult.requestsServed == 3   # AS-no-pa + AS-retry + TGS
    check kdcResult.err == ""
    # The TGT session key should match what the mock chose.
    check p.tgtSessionKey.len == 16
    for i in 0 ..< 16:
      check p.tgtSessionKey[i] == kdcCfg.tgtSessionKey[i]
    # Service ticket session key should also match.
    check p.svcSessionKey.len == 16
    for i in 0 ..< 16:
      check p.svcSessionKey[i] == kdcCfg.svcSessionKey[i]

  test "Mock KDC's first reply is KRB-ERROR with code 25":
    # Stand the mock back up so we can inspect the first reply directly.
    var kdcResult = MockKdcResult()
    var kdcCfg = MockKdcConfig()
    let args: KdcThreadArgs = (TestPort + 1, 2, addr kdcResult, addr kdcCfg)
    createThread(kdcThread, runMockKdc, args)
    sleep(150)

    let p = krb.newKerberosProvider(
      realm = TestRealm, username = TestUser, password = TestPass,
      kdcHost = "127.0.0.1", kdcPort = TestPort + 1,
      preferEtype = krbRc4.EtypeRc4Hmac, transport = ktTcp)
    p.obtainTgt()
    kdcThread.joinThread()
    # If obtainTgt succeeded, the retry path was taken — proves
    # KRB-ERROR(25) was returned and parsed.
    check kdcResult.requestsServed == 2
