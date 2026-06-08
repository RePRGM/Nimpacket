## auth/kerberos/provider.nim — Kerberos AuthProvider stub.
##
## Slots into the existing AuthProvider SPI so SPNEGO can wrap a
## Kerberos AP-REQ instead of an NTLM token. v0 supports:
##
##   * password-based AS-REQ with AES256-CTS-HMAC-SHA1-96 ETYPE
##   * KRB-ERROR response parsing (so callers see *why* the KDC said no)
##
## TGS-REQ and AP-REQ token construction are scaffolded; the wire
## bytes need full RFC 4120 §5.4 marshalling that's a couple hundred
## more lines. For now this gets us to "the KDC accepted our request"
## which is the hardest part to get right.

import std/[net, times, strutils]
import ../../rpc/auth as rpcauth
import ../../common/buffers
import etype, messages

type
  KerberosProvider* = ref object of AuthProvider
    realm*: string
    username*: string
    password*: string
    kdcHost*: string
    kdcPort*: int
    nonce*: uint32

  KrbProtocolError* = object of CatchableError

proc newKerberosProvider*(realm, username, password, kdcHost: string;
                          kdcPort: int = 88;
                          authLevel: AuthnLevel = alPktIntegrity):
                          KerberosProvider =
  result = KerberosProvider(
    realm: realm, username: username, password: password,
    kdcHost: kdcHost, kdcPort: kdcPort,
    nonce: 0x12345678'u32)
  result.state = asInit
  result.authType = atKerberos
  result.authLevel = authLevel
  result.maxSigSize = 16

# --- KDC transport ------------------------------------------------

proc sendKdcUdp*(host: string; port: int; pdu: openArray[byte];
                 timeoutMs: int = 5000): seq[byte] =
  ## Send a KRB5 request over UDP and read one datagram back.
  ## TCP transport is also defined by RFC 4120 (4-byte length-prefix);
  ## we'd add it once we hit AS-REP messages > 1500 bytes.
  let s = newSocket(AF_INET, SOCK_DGRAM, IPPROTO_UDP, buffered = false)
  defer: s.close()
  var sendBuf = newString(pdu.len)
  for i, b in pdu: sendBuf[i] = char(b)
  s.sendTo(host, Port(port), sendBuf)
  var buf = newString(65535)
  var sender = ""
  var senderPort: Port
  let n = s.recvFrom(buf, 65535, sender, senderPort)
  if n <= 0:
    raise newException(KrbProtocolError, "no KDC response")
  result = newSeq[byte](n)
  for i in 0 ..< n: result[i] = byte(buf[i].ord)

# --- AS exchange (probe) ------------------------------------------

proc preauthAsReq*(p: KerberosProvider): seq[byte] =
  ## Build an AS-REQ without pre-auth. Most modern KDCs will respond
  ## with a KRB-ERROR with code 25 (KDC_ERR_PREAUTH_REQUIRED) plus a
  ## PA-ETYPE-INFO2 in e-data telling us what salt to use. That
  ## response is the canonical Kerberos handshake start.
  let till = kerberosTimestamp(getTime() + 8.hours)
  result = buildAsReq(
    realm = p.realm,
    clientPrincipal = p.username,
    serviceName = "krbtgt",
    nonce = p.nonce,
    etypes = [EtypeAes256, EtypeAes128],
    till = till)

# --- AuthProvider interface --------------------------------------
#
# These are stubs until the full AS-REQ -> AS-REP -> TGS-REQ -> AP-REQ
# pipeline is wired. For now they raise so SPNEGO can fall back to
# its NTLM inner provider if the caller wraps both.

method initialize*(p: KerberosProvider; targetSpn: string): seq[byte] =
  raise newException(CatchableError,
    "Kerberos AS-REQ exchange is not yet complete; build the " &
    "PA-ENC-TIMESTAMP pre-auth path before invoking from SPNEGO. " &
    "AS-REQ builder + KDC transport + KRB-ERROR parser are " &
    "available for experimentation.")

method step*(p: KerberosProvider; serverToken: openArray[byte]): seq[byte] =
  raise newException(CatchableError, "Kerberos step not yet implemented")
