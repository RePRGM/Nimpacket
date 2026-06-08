## crypto/rand.nim — cross-platform CSPRNG wrapper.
##
## std/sysrand backs us on Linux (getrandom), Windows (BCryptGenRandom),
## macOS (CCRandomGenerateBytes), and BSDs. Returns ``false`` only on
## kernels old enough to lack any of those, which we treat as fatal
## (a crypto library without entropy is worse than useless).

import std/sysrand

type
  CsprngError* = object of CatchableError

proc randomBytes*(n: int): seq[byte] =
  ## ``n`` cryptographically random bytes.
  result = newSeq[byte](n)
  if n == 0: return
  if not urandom(result):
    raise newException(CsprngError, "OS CSPRNG unavailable")

proc randomBytes*(out_buf: var openArray[byte]) =
  if out_buf.len == 0: return
  if not urandom(out_buf):
    raise newException(CsprngError, "OS CSPRNG unavailable")
