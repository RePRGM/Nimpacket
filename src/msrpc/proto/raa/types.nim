## proto/raa/types.nim — MS-RAA §2.2 type definitions.
##
## Interface UUID: 0b1c2170-5732-4e0e-8cd3-d9b16f3b84d7, version 0.0.
## Interface URL: https://learn.microsoft.com/openspecs/windows_protocols/ms-raa/
##
## All types here are the on-wire forms (NDR-marshalled). Marshalling
## procs live in idl.nim.

import ../../common/[sid, guid]

const RaaInterfaceUuid* = "0b1c2170-5732-4e0e-8cd3-d9b16f3b84d7"
const RaaInterfaceMajor* = 0'u16
const RaaInterfaceMinor* = 0'u16

# --- Context handle (MS-DTYP §2.2.6 RPC_CONTEXT_HANDLE) ----------------

type
  AuthzrContextHandle* = object
    ## 20-byte opaque context handle.
    handleAttr*: uint32
    handleUuid*: Uuid

# --- AUTHZR_ACCESS_REQUEST (§2.2.1.2.1) --------------------------------

type
  AuthzrAccessRequest* = object
    desiredAccess*: uint32
    principalSelfSid*: ref Sid        ## nil ⇒ NULL on wire (unique ptr)
    objectTypeList*: seq[ObjectTypeListEntry]
    optionalArgumentsBytes*: seq[byte]   ## opaque pass-through

  ObjectTypeListEntry* = object
    level*: uint16
    sbz*: uint16            ## must be zero
    accessMask*: uint32
    objectType*: Uuid

# --- AUTHZR_ACCESS_REPLY (§2.2.1.2.2) ----------------------------------

type
  AuthzrAccessReply* = object
    resultListLength*: uint32
    grantedAccessMask*: seq[uint32]    ## resultListLength entries
    saclEvaluationResults*: seq[uint32]
    error*: seq[uint32]

# --- Compound-context flags (§2.2.1.1) ---------------------------------

const
  AUTHZ_COMPUTE_PRIVILEGES* = 0x00000008'u32

# --- Information classes for GetInformationFromContext -----------------

type
  AuthzContextInformationClass* = enum
    AuthzContextInfoUserSid              = 1
    AuthzContextInfoGroupsSids           = 2
    AuthzContextInfoRestrictedSids       = 3
    AuthzContextInfoPrivileges           = 4
    AuthzContextInfoExpirationTime       = 5
    AuthzContextInfoServerContext        = 6
    AuthzContextInfoIdentifier           = 7
    AuthzContextInfoSource               = 8
    AuthzContextInfoAll                  = 9
    AuthzContextInfoAuthenticationId     = 10
    AuthzContextInfoSecurityAttributes   = 11
    AuthzContextInfoDeviceSids           = 12
    AuthzContextInfoUserClaims           = 13
    AuthzContextInfoDeviceClaims         = 14
