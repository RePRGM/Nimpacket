## auth/kerberos/s4u.nim — MS-SFU S4U2self PA-FOR-USER builder.
##
## S4U2self lets a service obtain a ticket *to itself* on behalf of an
## arbitrary user, without that user's credentials — the basis for protocol
## transition and the first half of constrained delegation. It is driven by
## a PA-FOR-USER pre-auth element (padata type 129) in a TGS-REQ:
##
##   PA-FOR-USER ::= SEQUENCE {
##       userName     [0] PrincipalName,
##       userRealm    [1] Realm,
##       cksum        [2] Checksum,
##       auth-package [3] KerberosString ("Kerberos")
##   }
##
## The checksum is taken over LE32(name-type) ‖ userName ‖ userRealm ‖
## auth-package, keyed by the service's TGT session key with key usage
## KERB_NON_KERB_CKSUM_SALT (17). This module implements the RC4 case
## (KERB_CHECKSUM_HMAC_MD5, type -138).
##
## Reference: MS-SFU §2.2.1. Checksum + DER cross-checked byte-for-byte
## against impacket (getST) and RFC 4757 §4.

import ../../common/buffers
import ../../crypto/md5
import ../../crypto/hmac
import ../spnego/asn1
import messages
import tgsreq

const
  PaForUser* = 129                        ## padata-type for PA-FOR-USER
  PaPacOptions* = 167                      ## padata-type for PA-PAC-OPTIONS (RBCD)
  CksumHmacMd5* = -138                     ## KERB_CHECKSUM_HMAC_MD5 (RC4 sessions)
  KerbNonKerbCksumSalt* = 17'u32           ## key usage for the S4U checksum
  signatureKey = "signaturekey\x00"

proc kerbChecksumHmacMd5*(key: openArray[byte]; usage: uint32;
                          data: openArray[byte]): array[16, byte] =
  ## KERB_CHECKSUM_HMAC_MD5 (RFC 4757 §4):
  ##   Ksign = HMAC-MD5(key, "signaturekey\0")
  ##   tmp   = MD5(LE32(usage) ‖ data)
  ##   cksum = HMAC-MD5(Ksign, tmp)
  let ksign = hmacMd5(key, cast[seq[byte]](signatureKey))
  var tmp = newSeq[byte](4 + data.len)
  tmp[0] = byte(usage and 0xff)
  tmp[1] = byte((usage shr 8) and 0xff)
  tmp[2] = byte((usage shr 16) and 0xff)
  tmp[3] = byte((usage shr 24) and 0xff)
  for i, b in data: tmp[4 + i] = b
  let digest = md5(tmp)
  result = hmacMd5(ksign, digest)

proc s4uByteArray*(nameType: int; userName, userRealm, authPackage: string): seq[byte] =
  ## The exact byte sequence the PA-FOR-USER checksum is computed over:
  ## a 4-byte little-endian name-type followed by the three strings.
  result = @[byte(nameType and 0xff), byte((nameType shr 8) and 0xff),
             byte((nameType shr 16) and 0xff), byte((nameType shr 24) and 0xff)]
  result.add cast[seq[byte]](userName)
  result.add cast[seq[byte]](userRealm)
  result.add cast[seq[byte]](authPackage)

proc derSignedInt*(v: int): seq[byte] =
  ## Minimal two's-complement big-endian content bytes for a DER INTEGER,
  ## handling the negative Kerberos checksum types (e.g. -138).
  let u = cast[uint32](int32(v))
  result = @[byte((u shr 24) and 0xff), byte((u shr 16) and 0xff),
             byte((u shr 8) and 0xff), byte(u and 0xff)]
  while result.len > 1 and
        ((result[0] == 0x00 and (result[1] and 0x80) == 0) or
         (result[0] == 0xFF and (result[1] and 0x80) != 0)):
    result.delete(0)

proc buildPaForUser*(userName, userRealm: string; tgtSessionKey: openArray[byte];
                     nameType = NtPrincipal; authPackage = "Kerberos";
                     cksumType = CksumHmacMd5): seq[byte] =
  ## Build the DER-encoded PA-FOR-USER for an S4U2self request, computing the
  ## checksum with ``tgtSessionKey`` (the service's own TGT session key).
  ## Currently emits the RC4 (HMAC-MD5) checksum.
  let s4u = s4uByteArray(nameType, userName, userRealm, authPackage)
  let chk = kerbChecksumHmacMd5(tgtSessionKey, KerbNonKerbCksumSalt, s4u)

  let userNameTag = fieldTag(0, principalName(nameType, [userName]))
  let userRealmTag = fieldTag(1, derTLV(0x1B'u8, cast[seq[byte]](userRealm)))

  let cksumInner = newBuffer()
  cksumInner.writeBytes(fieldTag(0, derTLV(0x02'u8, derSignedInt(cksumType))))
  cksumInner.writeBytes(fieldTag(1, derTLV(tagOctetString, @chk)))
  let cksumTag = fieldTag(2, derTLV(tagSequence, cksumInner.consumed))

  let authPkgTag = fieldTag(3, derTLV(0x1B'u8, cast[seq[byte]](authPackage)))

  let body = newBuffer()
  body.writeBytes(userNameTag)
  body.writeBytes(userRealmTag)
  body.writeBytes(cksumTag)
  body.writeBytes(authPkgTag)
  result = derTLV(tagSequence, body.consumed)

# --- S4U2self / S4U2proxy TGS-REQ builders --------------------------

proc buildS4U2self*(realm: string;
                    serviceName: openArray[string];
                    userName, userRealm: string;
                    tgtSessionKey: openArray[byte];
                    nonce: uint32;
                    etypes: openArray[uint32];
                    till: string;
                    apReq: openArray[byte];
                    serviceNameType = NtPrincipal): seq[byte] =
  ## S4U2self: ask the KDC for a service ticket to ``serviceName`` (the
  ## requesting service's OWN principal) on behalf of ``userName@userRealm``.
  ## ``apReq`` is the service's AP-REQ to krbtgt; ``tgtSessionKey`` is that
  ## TGT's session key (used to checksum the PA-FOR-USER).
  let pfu = buildPaForUser(userName, userRealm, tgtSessionKey)
  let sname = principalName(serviceNameType, serviceName)
  result = buildTgsReqRaw(realm, sname, nonce, etypes, till, apReq,
    kdcFlags = kdcOptionFlags([KdcOptForwardable, KdcOptRenewable, KdcOptCanonicalize]),
    extraPaData = paDataEntry(PaForUser, pfu))

proc buildS4U2proxy*(realm: string;
                     targetService: openArray[string];
                     evidenceTicket: openArray[byte];
                     nonce: uint32;
                     etypes: openArray[uint32];
                     till: string;
                     apReq: openArray[byte];
                     targetNameType = NtSrvHst;
                     pacOptions: openArray[byte] = @[]): seq[byte] =
  ## S4U2proxy: present the S4U2self ``evidenceTicket`` (a forwardable service
  ## ticket for the user) and ask for a ticket to ``targetService`` on the
  ## user's behalf. Sets the cname-in-addl-tkt KDC option and places the
  ## evidence ticket in req-body [11]. ``pacOptions``, if given, is a
  ## pre-encoded PA-PAC-OPTIONS value appended as padata (for RBCD).
  let sname = principalName(targetNameType, targetService)
  var extra: seq[byte]
  if pacOptions.len > 0:
    extra = paDataEntry(PaPacOptions, pacOptions)
  result = buildTgsReqRaw(realm, sname, nonce, etypes, till, apReq,
    kdcFlags = kdcOptionFlags([KdcOptForwardable, KdcOptRenewable,
                               KdcOptCnameInAddlTkt, KdcOptCanonicalize]),
    extraPaData = extra,
    additionalTickets = evidenceTicket)
