## ntowf.nim — NTOWF / LMOWF helpers (MS-NLMP §3.3).
##
## ``NTOWFv1(P)        = MD4(UTF16LE(P))``
## ``NTOWFv2(P, U, D)  = HMAC_MD5(NTOWFv1(P), UTF16LE(UPPER(U) + D))``
## ``LMOWFv2          = NTOWFv2``
##
## The username is uppercased before concatenation; the domain is not.
## We do ASCII uppercase only — production Windows uses CharUpperW which
## is locale-aware, but every captured vector and every real-world AD
## username we'd want to interop with is ASCII-safe.

import ../../common/unicode
import ../../crypto/[md4, hmac]

proc asciiUpper(s: string): string =
  result = newString(s.len)
  for i, ch in s:
    if ch >= 'a' and ch <= 'z':
      result[i] = chr(ord(ch) - 32)
    else:
      result[i] = ch

proc ntowfV1*(password: string): array[16, byte] =
  ## MD4 of the UTF-16LE password.
  md4(toUtf16Bytes(password))

proc ntowfV2*(password, user, domain: string): array[16, byte] =
  ## HMAC-MD5 of UTF-16LE(UPPER(user) || domain) keyed by NTOWFv1(password).
  let key = ntowfV1(password)
  let concat = asciiUpper(user) & domain
  let msg = toUtf16Bytes(concat)
  hmacMd5(key, msg)

proc lmowfV2*(password, user, domain: string): array[16, byte] {.inline.} =
  ## In NTLMv2, LMOWFv2 is identical to NTOWFv2.
  ntowfV2(password, user, domain)
