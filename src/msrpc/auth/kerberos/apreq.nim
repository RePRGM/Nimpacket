## auth/kerberos/apreq.nim — AP-REQ builder + GSS-API token wrap.
##
## AP-REQ ::= [APPLICATION 14] SEQUENCE {
##     pvno           [0] INTEGER (5),
##     msg-type       [1] INTEGER (14),
##     ap-options     [2] APOptions,
##     ticket         [3] Ticket,
##     authenticator  [4] EncryptedData    -- Authenticator
## }
##
## Authenticator ::= [APPLICATION 2] SEQUENCE {
##     authenticator-vno  [0] INTEGER (5),
##     crealm             [1] Realm,
##     cname              [2] PrincipalName,
##     cusec              [4] Microseconds,
##     ctime              [5] KerberosTime,
##     ...
## }
##
## GSS-API wrap (RFC 4121):
##   [APPLICATION 0] IMPLICIT SEQUENCE {
##     thisMech   OID 1.2.840.113554.1.2.2 (Kerberos),
##     <TOK_ID = 0x01 0x00> || AP-REQ-bytes
##   }
##
## TOK_ID 0x01 0x00 = "initial token".

import std/times
import ../../common/buffers
import ../spnego/asn1
import messages, preauth, rc4 as krbRc4

const KerberosMechOid* = [1, 2, 840, 113554, 1, 2, 2]

# --- Authenticator ----------------------------------------------

proc buildAuthenticator*(crealm, cname: string; ctime: Time;
                         cusec: int = 0): seq[byte] =
  let inner = newBuffer()
  # [0] authenticator-vno = 5
  inner.writeBytes(fieldTag(0, derTLV(0x02'u8, @[5'u8])))
  # [1] crealm
  inner.writeBytes(fieldTag(1, derTLV(0x1B'u8, cast[seq[byte]](crealm))))
  # [2] cname
  inner.writeBytes(fieldTag(2, principalName(NtPrincipal, [cname])))
  # [4] cusec
  var usecBytes: seq[byte] = @[]
  var u = cusec
  while u > 0:
    usecBytes.insert(byte(u and 0xff), 0)
    u = u shr 8
  if usecBytes.len == 0: usecBytes = @[0'u8]
  if (usecBytes[0] and 0x80) != 0: usecBytes.insert(0'u8, 0)
  inner.writeBytes(fieldTag(4, derTLV(0x02'u8, usecBytes)))
  # [5] ctime
  inner.writeBytes(fieldTag(5,
    derTLV(0x18'u8, cast[seq[byte]](kerberosTimestamp(ctime)))))
  result = derTLV(appConstructed(2), derTLV(tagSequence, inner.consumed))

# --- AP-REQ ---------------------------------------------------------

proc buildApReq*(sessionKey: openArray[byte];
                 ticketBytes: openArray[byte];
                 crealm, cname: string;
                 ctime: Time;
                 mutualAuth: bool = false): seq[byte] =
  ## Build a complete AP-REQ. Authenticator is encrypted under the
  ## session key with usage = 11 (AP-REQ authenticator) per RFC 4120
  ## §7.5.1 (RFC 4757 §3 for RC4-HMAC).
  let auth = buildAuthenticator(crealm, cname, ctime)
  let authEnc = krbRc4.rc4HmacEncrypt(sessionKey, auth, usage = 11)
  let authEncData = buildEncryptedData(krbRc4.EtypeRc4Hmac, authEnc)

  let inner = newBuffer()
  inner.writeBytes(fieldTag(0, derTLV(0x02'u8, @[5'u8])))         # pvno
  inner.writeBytes(fieldTag(1, derTLV(0x02'u8,
                                       @[byte(appApReq)])))
  # [2] ap-options : BIT STRING (32 bits)
  var apOpt: array[5, byte]
  apOpt[0] = 0   # unused bits
  if mutualAuth:
    # bit 1 = mutual-required (positional bit 1, MSB-first)
    apOpt[1] = 0x40'u8
  inner.writeBytes(fieldTag(2, derTLV(tagBitString, @apOpt)))
  # [3] ticket (raw)
  inner.writeBytes(fieldTag(3, ticketBytes))
  # [4] authenticator
  inner.writeBytes(fieldTag(4, authEncData))

  result = derTLV(appConstructed(appApReq),
                   derTLV(tagSequence, inner.consumed))

# --- GSS-API wrap --------------------------------------------------

proc wrapGssApReq*(apReq: openArray[byte]): seq[byte] =
  ## RFC 4121 §4.1: GSS-API initial token. Outer is [APPLICATION 0]
  ## SEQUENCE { mech-oid, TOK_ID(0x01 0x00) || inner }
  let mech = derEncodeOid(@KerberosMechOid)
  var inner = newSeq[byte](2 + apReq.len)
  inner[0] = 0x01     # TOK_ID byte 0
  inner[1] = 0x00     # TOK_ID byte 1
  for i in 0 ..< apReq.len: inner[2 + i] = apReq[i]
  let payload = newBuffer()
  payload.writeBytes(mech)
  payload.writeBytes(inner)
  result = derTLV(appConstructed(0), payload.consumed)
