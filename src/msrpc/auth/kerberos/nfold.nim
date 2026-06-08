## auth/kerberos/nfold.nim — RFC 3961 §5.1 "n-fold" function.
##
## Port of MIT Kerberos' canonical byte-oriented implementation. Used
## as part of DR (RFC 3961 §5.3) to derive per-usage subkeys for
## AES-CTS-HMAC-SHA1-96 (RFC 3962).

proc nfold*(src: openArray[byte]; nBits: int): seq[byte] =
  doAssert nBits mod 8 == 0, "n-fold output must be byte-aligned"
  doAssert src.len > 0
  let inbits = src.len                # bytes
  let outbits = nBits div 8           # bytes
  # lcm(outbits, inbits) using Euclid's gcd
  var a = outbits
  var b = inbits
  while b != 0:
    let c = b
    b = a mod b
    a = c
  let lcm = outbits * inbits div a

  result = newSeq[byte](outbits)
  var byteAcc = 0
  for i in countdown(lcm - 1, 0):
    # msbit position within the M-bit input that this output bit reads.
    let msbit = (
      ((inbits shl 3) - 1) +
      (((inbits shl 3) + 13) * (i div inbits)) +
      ((inbits - (i mod inbits)) shl 3)
    ) mod (inbits shl 3)
    # Pull out the byte value (need two consecutive input bytes to
    # straddle non-byte-aligned reads).
    let idx1 = ((inbits - 1) - (msbit shr 3)) mod inbits
    let idx2 = (inbits - (msbit shr 3)) mod inbits
    let combined = (int(src[idx1]) shl 8) or int(src[idx2])
    let bv = (combined shr ((msbit and 7) + 1)) and 0xff
    byteAcc += bv
    byteAcc += int(result[i mod outbits])
    result[i mod outbits] = byte(byteAcc and 0xff)
    byteAcc = byteAcc shr 8
  # Add residual carry back in.
  if byteAcc != 0:
    for i in countdown(outbits - 1, 0):
      byteAcc += int(result[i])
      result[i] = byte(byteAcc and 0xff)
      byteAcc = byteAcc shr 8
