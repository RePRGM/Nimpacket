import std/unittest
import msrpc/crypto/rand

suite "csprng":
  test "returns the requested length":
    check randomBytes(0).len == 0
    check randomBytes(1).len == 1
    check randomBytes(16).len == 16
    check randomBytes(1024).len == 1024

  test "not all zero (overwhelming probability)":
    let r = randomBytes(64)
    var allZero = true
    for b in r:
      if b != 0: allZero = false; break
    check (not allZero)

  test "two draws differ":
    let a = randomBytes(32)
    let b = randomBytes(32)
    check a != b
