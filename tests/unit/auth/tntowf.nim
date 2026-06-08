## MS-NLMP §4.2.2 (NTLMv2) worked-example values.
##   User     = "User"
##   Domain   = "Domain"
##   Password = "Password"
##   ResponseKeyNT (= NTOWFv2) = 0x0c868a403bfd7a93a3001ef22ef02e3f

import std/[unittest, strutils]
import msrpc/auth/ntlm/ntowf

proc hex(d: openArray[byte]): string =
  for b in d: result.add toHex(int(b), 2).toLowerAscii

suite "ntowf (MS-NLMP §4.2)":
  test "NTOWFv1(Password) §4.2.2":
    # §4.2.2 NTOWFv1("Password") = 0xa4f49c406510bdcab6824ee7c30fd852
    check hex(ntowfV1("Password")) == "a4f49c406510bdcab6824ee7c30fd852"

  test "NTOWFv2(\"Password\", \"User\", \"Domain\") §4.2.2":
    check hex(ntowfV2("Password", "User", "Domain")) ==
      "0c868a403bfd7a93a3001ef22ef02e3f"

  test "LMOWFv2 == NTOWFv2":
    check lmowfV2("Password", "User", "Domain") ==
      ntowfV2("Password", "User", "Domain")

  test "user is uppercased, domain is not":
    # Lowercase user should produce the same result because we uppercase it.
    check ntowfV2("Password", "user", "Domain") ==
      ntowfV2("Password", "User", "Domain")
    # Lowercase domain should NOT produce the same result.
    check ntowfV2("Password", "User", "domain") !=
      ntowfV2("Password", "User", "Domain")
