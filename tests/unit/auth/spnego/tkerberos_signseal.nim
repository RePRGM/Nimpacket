## SPNEGO+Kerberos at alPktIntegrity: rpcSignSeal produces a MIC
## token that rpcUnsealVerify accepts. Tampering with either the
## body or the verifier breaks verification.

import std/unittest
import msrpc/rpc/auth as rpcauth
import msrpc/auth/kerberos/provider as krb
import msrpc/auth/spnego/provider as spnego
import msrpc/auth/kerberos/etype

proc str(s: string): seq[byte] =
  result = newSeq[byte](s.len)
  for i, c in s: result[i] = byte(c)

proc mockEstablished(k: krb.KerberosProvider; sessionKey: openArray[byte]) =
  ## Skip the AS/TGS exchange and pretend we've already negotiated a
  ## service session key with the peer.
  k.svcSessionKey = newSeq[byte](sessionKey.len)
  for i, b in sessionKey: k.svcSessionKey[i] = b
  k.state = asEstablished

suite "SPNEGO + Kerberos rpcSignSeal at alPktIntegrity":
  test "MIC round-trip across two peers with the same session key":
    let key = stringToKey(str("password"), str("ATHENA.MIT.EDUraeburn"),
                          EtypeAes128, iterations = 1)
    # Client side
    let kc = krb.newKerberosProvider("R", "u", "p", "kdc",
                                     authLevel = alPktIntegrity)
    kc.mockEstablished(key)
    let spc = spnego.newSpnegoKerberos(kc)
    spc.authLevel = alPktIntegrity
    # Server side: same session key, but role = acceptor.
    let ks = krb.newKerberosProvider("R", "u", "p", "kdc",
                                     authLevel = alPktIntegrity,
                                     role = krAcceptor)
    ks.mockEstablished(key)
    let sps = spnego.newSpnegoKerberos(ks)
    sps.authLevel = alPktIntegrity

    # Client: sign a PDU body
    var body = str("ECHO REQUEST body goes here")
    let sigLen = body.len
    let verifier = spc.rpcSignSeal(body, sigLen)
    check verifier.len == 16 + 12        # TokenHeader(16) + HMAC(12)

    # Server: verify with its own provider (different sndSeq/rcvSeq
    # state, but same session key + sequence numbers start at 0)
    var bodyCopy = body                  # data is unchanged for MIC
    let ok = sps.rpcUnsealVerify(bodyCopy, sigLen, verifier)
    check ok

  test "tampering with the body fails verification":
    let key = stringToKey(str("password"), str("salt"),
                          EtypeAes128, iterations = 50)
    let kc = krb.newKerberosProvider("R", "u", "p", "kdc",
                                     authLevel = alPktIntegrity)
    kc.mockEstablished(key)
    let spc = spnego.newSpnegoKerberos(kc)
    spc.authLevel = alPktIntegrity
    let ks = krb.newKerberosProvider("R", "u", "p", "kdc",
                                     authLevel = alPktIntegrity,
                                     role = krAcceptor)
    ks.mockEstablished(key)
    let sps = spnego.newSpnegoKerberos(ks)
    sps.authLevel = alPktIntegrity

    var body = str("legitimate request")
    let verifier = spc.rpcSignSeal(body, body.len)
    var tampered = str("legitimate REPLAY")  # same length, different bytes
    let ok = sps.rpcUnsealVerify(tampered, tampered.len, verifier)
    check not ok

  test "alPktPrivacy: WrapEx round-trip seals and recovers body":
    let key = stringToKey(str("password"), str("ATHENA.MIT.EDUraeburn"),
                          EtypeAes256, iterations = 1)
    let kc = krb.newKerberosProvider("R", "u", "p", "kdc",
                                     authLevel = alPktPrivacy)
    kc.mockEstablished(key)
    let spc = spnego.newSpnegoKerberos(kc)
    spc.authLevel = alPktPrivacy
    let ks = krb.newKerberosProvider("R", "u", "p", "kdc",
                                     authLevel = alPktPrivacy,
                                     role = krAcceptor)
    ks.mockEstablished(key)
    let sps = spnego.newSpnegoKerberos(ks)
    sps.authLevel = alPktPrivacy

    let plain = str("encrypted RPC body bytes!!!")
    var body = plain                    # plain copy we'll send sealed
    let verifier = spc.rpcSignSeal(body, body.len)
    check verifier.len == 60            # WrapEx Header(32) + Trailer(28)
    check body != plain                 # actually encrypted

    let ok = sps.rpcUnsealVerify(body, body.len, verifier)
    check ok
    check body == plain                 # decrypted back

  test "alPktPrivacy: tampering with the sealed body fails":
    let key = stringToKey(str("password"), str("salt"),
                          EtypeAes128, iterations = 50)
    let kc = krb.newKerberosProvider("R", "u", "p", "kdc",
                                     authLevel = alPktPrivacy)
    kc.mockEstablished(key)
    let spc = spnego.newSpnegoKerberos(kc)
    spc.authLevel = alPktPrivacy
    let ks = krb.newKerberosProvider("R", "u", "p", "kdc",
                                     authLevel = alPktPrivacy,
                                     role = krAcceptor)
    ks.mockEstablished(key)
    let sps = spnego.newSpnegoKerberos(ks)
    sps.authLevel = alPktPrivacy

    var body = str("seal me")
    let verifier = spc.rpcSignSeal(body, body.len)
    body[3] = body[3] xor 0x01          # corrupt the ciphertext
    let ok = sps.rpcUnsealVerify(body, body.len, verifier)
    check not ok

suite "KerberosProvider per-message GSS Wrap / MIC":
  test "krbWrapData/krbUnwrapData round-trip with sequence number bump":
    let key = stringToKey(str("password"), str("ATHENA.MIT.EDUraeburn"),
                          EtypeAes256, iterations = 1)
    let kc = krb.newKerberosProvider("R", "u", "p", "kdc")
    kc.mockEstablished(key)
    let ks = krb.newKerberosProvider("R", "u", "p", "kdc",
                                     role = krAcceptor)
    ks.mockEstablished(key)

    let plain = str("hello kerberos sealed world")
    let token = kc.krbWrapData(plain)
    check kc.sndSeq == 1'u64                # bumped after wrap

    let (rec, ok) = ks.krbUnwrapData(token)
    check ok
    check rec == plain
    check ks.rcvSeq == 1'u64                # bumped after unwrap

  test "krbUnwrapData rejects out-of-order sequence numbers":
    let key = stringToKey(str("password"), str("salt"),
                          EtypeAes128, iterations = 50)
    let kc = krb.newKerberosProvider("R", "u", "p", "kdc")
    kc.mockEstablished(key)
    let ks = krb.newKerberosProvider("R", "u", "p", "kdc",
                                     role = krAcceptor)
    ks.mockEstablished(key)

    discard kc.krbWrapData(str("message zero"))       # sndSeq 0 → 1
    let t1 = kc.krbWrapData(str("message one"))       # sndSeq 1 → 2
    # Server hasn't consumed message zero, so expects seq 0 but gets 1.
    let (_, ok) = ks.krbUnwrapData(t1)
    check not ok
    check ks.rcvSeq == 0'u64                          # unchanged
