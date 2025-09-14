import ../RPC/rpc
import ../RPC/ndr
import std/[strformat, options, strutils]

# ==================== Test/Example Usage ====================

when isMainModule:
  echo "NDR Library Examples\n"
  echo "=".repeat(50)
  
  # Example 1: NetrShareEnum
  echo "\n1. NetrShareEnum Request:"
  var container1 = ShareInfoContainer1(entriesRead: 0, buffer: @[])
  var shareEnum = ShareEnum(level: silLevel1, container: addr container1)
  var totalEntries: uint32 = 0
  var resumeHandle: uint32 = 0
  
  let shareEnumData = NetrShareEnum(
    "\\\\WIN-SERVER",
    addr shareEnum,
    0xFFFFFFFF'u32,
    addr totalEntries,
    addr resumeHandle
  )
  
  echo fmt"Encoded {shareEnumData.len} bytes:"
  for i in 0..<min(64, shareEnumData.len):
    if i mod 16 == 0:
      echo ""
    stdout.write(fmt"{shareEnumData[i]:02x} ")
  echo "\n..."
  
  # Example 2: SamrConnect5
  echo "\n2. SamrConnect5 Request:"
  let samrConnectData = SamrConnect5(
    "\\\\WIN-DC01",
    0x02000000'u32  # MAXIMUM_ALLOWED
  )
  
  echo fmt"Encoded {samrConnectData.len} bytes:"
  for i in 0..<min(64, samrConnectData.len):
    if i mod 16 == 0:
      echo ""
    stdout.write(fmt"{samrConnectData[i]:02x} ")
  echo "\n..."
  
  # Example 3: LsaOpenPolicy2
  echo "\n3. LsaOpenPolicy2 Request:"
  var objName = LsaUnicodeString(
    length: 0,
    maximumLength: 0,
    buffer: ""
  )
  
  let objAttrs = LsaObjectAttributes(
    length: 24,
    rootDirectory: default(LsaHandle),
    objectName: nil,
    attributes: 0,
    securityDescriptor: nil,
    securityQualityOfService: nil
  )
  
  let lsaOpenData = LsaOpenPolicy2(
    "\\\\WIN-DC01",
    objAttrs,
    0x02000000'u32
  )
  
  echo fmt"Encoded {lsaOpenData.len} bytes:"
  for i in 0..<min(64, lsaOpenData.len):
    if i mod 16 == 0:
      echo ""
    stdout.write(fmt"{lsaOpenData[i]:02x} ")
  echo "\n..."
  
  # Example 4: Decoding
  echo "\n4. Decoding Example:"
  
  # Create a mock response that matches actual NDR wire format
  let mockBuf = newNDRBuffer()
  
  # === Main structure ===
  # Level
  encodeUint32(mockBuf, silLevel1.ord.uint32)
  
  # Union discriminant
  encodeUint32(mockBuf, 1'u32)
  
  # Container entriesRead
  encodeUint32(mockBuf, 2'u32)
  
  # Buffer pointer (non-null)
  encodeUint32(mockBuf, 0x20000'u32)
  
  # TotalEntries
  encodeUint32(mockBuf, 2'u32)
  
  # ResumeHandle pointer (null)
  encodeUint32(mockBuf, 0'u32)
  
  # === Deferred pointer data section ===
  # Conformant array header
  encodeUint32(mockBuf, 2'u32)  # array count
  
  # First ShareInfo1
  mockBuf.align(Align4)
  encodeUint32(mockBuf, 0x20001'u32)  # netName pointer
  encodeUint32(mockBuf, stDiskTree.ord.uint32)  # shareType
  mockBuf.align(Align4)
  encodeUint32(mockBuf, 0x20002'u32)  # remark pointer
  
  # Second ShareInfo1
  mockBuf.align(Align4)
  encodeUint32(mockBuf, 0x20003'u32)  # netName pointer
  encodeUint32(mockBuf, stDiskTree.ord.uint32)  # shareType
  mockBuf.align(Align4)
  encodeUint32(mockBuf, 0x20004'u32)  # remark pointer
  
  # === Deferred string data ===
  # CRITICAL: Deferred data appears in ENCOUNTER ORDER, not grouped by field
  # First struct's strings
  encodeConformantString(mockBuf, "ADMIN$")       # First struct's netName (ref 0x20001)
  encodeConformantString(mockBuf, "Remote Admin")  # First struct's remark (ref 0x20002)
  
  # Second struct's strings  
  encodeConformantString(mockBuf, "C$")            # Second struct's netName (ref 0x20003)
  encodeConformantString(mockBuf, "Default share") # Second struct's remark (ref 0x20004)
  
  # Status at the end
  encodeUint32(mockBuf, 0'u32)  # SUCCESS
  
  # Now decode it
  let decoded = decodeNetrShareEnumResponse(mockBuf.data)
  echo fmt"Decoded level: {decoded.level}"
  echo fmt"Decoded entries: {decoded.container.entriesRead}"
  echo fmt"Total entries: {decoded.totalEntries}"
  echo fmt"Status: 0x{decoded.status:08x}"
  
  if decoded.container.buffer.len > 0:
    echo "Shares found:"
    for share in decoded.container.buffer:
      echo fmt"  - {share.netName} ({share.shareType}): {share.remark}"
  
  echo "\n" & "=".repeat(50)
  echo "Examples complete!"
