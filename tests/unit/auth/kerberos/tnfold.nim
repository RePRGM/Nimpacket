## RFC 3961 §A.1 n-fold test vectors.

import std/[unittest, strutils]
import msrpc/auth/kerberos/nfold

proc h(d: openArray[byte]): string =
  for b in d: result.add toHex(int(b), 2).toLowerAscii

proc str(s: string): seq[byte] =
  result = newSeq[byte](s.len)
  for i, c in s: result[i] = byte(c)

suite "RFC 3961 n-fold":
  test "64-fold(\"012345\") = be072631276b1955":
    check h(nfold(str("012345"), 64)) == "be072631276b1955"

  test "56-fold(\"password\") = 78a07b6caf85fa":
    check h(nfold(str("password"), 56)) == "78a07b6caf85fa"

  test "64-fold(\"kerberos\") = 6b65726265726f73":
    check h(nfold(str("kerberos"), 64)) == "6b65726265726f73"

  test "128-fold(\"kerberos\") = 6b65726265726f737b9b5b2b93132b93":
    check h(nfold(str("kerberos"), 128)) == "6b65726265726f737b9b5b2b93132b93"
