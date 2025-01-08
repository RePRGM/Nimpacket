from std/strutils import toHex

proc toUtf16LE*(s: string): seq[uint8] =
  result = newSeq[uint8](s.len * 2)
  var j = 0
  for i in 0 ..< s.len:
    result[j] = uint8(s[i])
    result[j + 1] = 0
    j += 2

proc dumpHex*(data: openArray[byte], prefix: string = "") =
  for b in data:
    stdout.write(b.toHex(2))
  stdout.write("\n")

proc dumpHexString*(data: string, length: int, prefix: string = "") =
  for i in 0..<length:
    stdout.write(cast[byte](data[i]).toHex(2))
  stdout.write("\n")

proc readUint32Le*(data: openArray[uint8], pos: int): uint32 =
  result = uint32(data[pos]) or
           uint32(data[pos + 1]) shl 8 or
           uint32(data[pos + 2]) shl 16 or
           uint32(data[pos + 3]) shl 24

proc readUtf16String*(data: openArray[uint8], pos: int, numChars: int): tuple[str: string, bytesRead: int] =
  var bytes = newSeq[uint8]()
  let byteCount = numChars * 2
  
  # Read the UTF16LE chars
  for i in countup(0, byteCount-2, 2):
    if pos + i + 1 >= data.len:
      break
    if data[pos + i] == 0 and data[pos + i + 1] == 0:
      break
    bytes.add(data[pos + i])
    bytes.add(data[pos + i + 1])
  
  if bytes.len > 0:
    try:
      result.str = cast[string](bytes)
    except:
      result.str = ""
  
  result.bytesRead = ((byteCount + 7) and not 7)