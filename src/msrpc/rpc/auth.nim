## rpc/auth.nim — security trailer + auth verifier exchange.
##
## MS-RPCE §2.2.2.11: the security trailer (``sec_trailer``) is an
## 8-byte struct that follows the stub data of a Request/Response PDU
## when ``auth_length > 0``. The auth verifier itself (output of the
## SSPI's MakeSignature/SealMessage) follows the sec_trailer.
##
## Sec_trailer layout::
##
##   auth_type            u8     RPC_C_AUTHN_*
##   auth_level           u8     RPC_C_AUTHN_LEVEL_*
##   auth_pad_length      u8     stub padding before the trailer (to 16-byte align)
##   auth_reserved        u8     0
##   auth_context_id      u32    per-connection AuthN context id

import ../common/[buffers, endian]

{.push warning[HoleEnumConv]: off.}

const SecTrailerLen* = 8

type
  AuthnLevel* = enum
    alNone           = 0
    alConnect        = 1
    alCall           = 2
    alPkt            = 3
    alPktIntegrity   = 4
    alPktPrivacy     = 5

  AuthnType* = enum
    ## Nim 2.0.x requires monotonically increasing values in
    ## explicitly-numbered enums; keep these in numeric order.
    atNone           = 0
    atGssNegotiate   = 9     ## SPNEGO (NEGOEX wraps this in newer Windows)
    atNtlm           = 10
    atSchannel       = 14    ## TLS-like RPC over Schannel
    atKerberos       = 16    ## raw Kerberos

  SecTrailer* = object
    authType*: AuthnType
    authLevel*: AuthnLevel
    padLength*: uint8
    reserved*: uint8
    contextId*: uint32

proc writeSecTrailer*(b: Buffer; t: SecTrailer) =
  b.writeByte(uint8(ord(t.authType)))
  b.writeByte(uint8(ord(t.authLevel)))
  b.writeByte(t.padLength)
  b.writeByte(t.reserved)
  b.writeU32LE(t.contextId)

proc readSecTrailer*(b: Buffer): SecTrailer =
  result.authType = AuthnType(b.readByte())
  result.authLevel = AuthnLevel(b.readByte())
  result.padLength = b.readByte()
  result.reserved = b.readByte()
  result.contextId = b.readU32LE()

# --- AuthProvider interface ---------------------------------------------

type
  AuthState* = enum
    asInit
    asContinue
    asEstablished
    asFailed

  AuthProvider* = ref object of RootObj
    state*: AuthState
    authType*: AuthnType
    authLevel*: AuthnLevel
    maxSigSize*: int        ## bytes added per outbound message

method initialize*(p: AuthProvider; targetSpn: string): seq[byte] {.base.} =
  ## Produce the first auth token (e.g. NTLM NEGOTIATE).
  raise newException(CatchableError, "initialize not implemented")

method step*(p: AuthProvider; serverToken: openArray[byte]): seq[byte] {.base.} =
  ## Process a server token and produce the next client token.
  raise newException(CatchableError, "step not implemented")

method sign*(p: AuthProvider; pdu: openArray[byte]): seq[byte] {.base.} =
  ## Produce the auth verifier for a signed-only PDU.
  raise newException(CatchableError, "sign not implemented")

method seal*(p: AuthProvider; pdu: var openArray[byte]): seq[byte] {.base.} =
  ## Encrypt ``pdu`` in place and produce the auth verifier.
  raise newException(CatchableError, "seal not implemented")

method verify*(p: AuthProvider; pdu: openArray[byte];
               verifier: openArray[byte]): bool {.base.} =
  ## Validate a verifier on an inbound signed-only PDU.
  raise newException(CatchableError, "verify not implemented")

method unseal*(p: AuthProvider; pdu: var openArray[byte];
               verifier: openArray[byte]): bool {.base.} =
  ## Decrypt ``pdu`` in place and validate the verifier.
  raise newException(CatchableError, "unseal not implemented")

method rpcSignSeal*(p: AuthProvider; data: var openArray[byte];
                    sealLen: int): seq[byte] {.base.} =
  ## RPC-flavoured sign+seal: encrypt ``data[0 ..< sealLen]`` in place
  ## using the provider's privacy/integrity scheme and return the
  ## sec_trailer.auth_value bytes.
  raise newException(CatchableError, "rpcSignSeal not implemented")

method rpcUnsealVerify*(p: AuthProvider; data: var openArray[byte];
                        sealLen: int;
                        verifier: openArray[byte]): bool {.base.} =
  ## Inverse of rpcSignSeal.
  raise newException(CatchableError, "rpcUnsealVerify not implemented")
{.pop.}
