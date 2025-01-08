proc createSpnegoToken*(ntlmMsg: seq[uint8], msgType: int): seq[uint8] =
  if msgType == 1:
    let 
      ntlmLength = ntlmMsg.len
      totalLength = 40 + ntlmLength # 2 Bytes (0x60 & len) + 8 Bytes (SPNEGO OID) + 10 Bytes (Inner Context Token Headers) + 10 Bytes (Mech Types Structures) + 10 Bytes (NTLMSSP OID) + 8 Bytes (NTLMSSP Signature) + ntlmMsg.len
      innerContextLen = totalLength - 10 # 2 Bytes (0x60 & len) + 2 Bytes (0x06 & len) + 6 Bytes (SPNEGO OID)
      seqLen = innerContextLen - 2 # 2 Bytes (0xa0 & len)
      mechTokenLen = ntlmLength + 10 # 2 Bytes (0xa2 & len) + 8 Bytes (NTLMSSP Signature)
    
    #echo "Lengths: "
    #echo "createSpnegoToken ntlmLength: ", ntlmLength
    #echo "createSpnegoToken totalLength: ", totalLength
    #echo "createSpnegoToken innerContextLen: ", innerContextLen
    #echo "createSpnegoToken seqLen: ", seqLen
    #echo "createSpnegoToken mechTOkenLen: ", mechTokenLen
    var token = @[0x60'u8, totalLength.uint8]
    token.add([0x06'u8, 0x06, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02]) # 1 Byte (ThisMechId), 1 Byte (ThisMechId Length), 6 Bytes (SPNEGO OID)
    token.add([0xa0'u8, innerContextLen.uint8, 0x30, seqLen.uint8])
    token.add([0xa0'u8, 0x0e, 0x30, 0x0c, 0x06, 0x0a])
    token.add([0x2b'u8, 0x06, 0x01, 0x04, 0x01, 0x82]) # NTLM SSP OID
    token.add([0x37'u8, 0x02, 0x02, 0x0a])
    token.add([0xa2'u8, mechTokenLen.uint8])
    token.add([0x04'u8, (ntlmLength+8).uint8])
    
    token.add([0x4E'u8, 0x54, 0x4C, 0x4D, 0x53, 0x53, 0x50, 0x00]) # NTLM SSP Signature
    token.add(ntlmMsg)
    #echo "createSpnegoToken Token Length: ", token.len
    return token
  elif msgType == 3:
    let 
        ntlmLength = ntlmMsg.len    # NTLM Type 3 message length
        octetStringLength = ntlmLength
        tokenLength = octetStringLength + 4
        sequenceLength = tokenLength + 4
        totalLength = sequenceLength + 4

    var token = @[
    0xa1'u8, 0x82,                                    # NegTokenResp, long form
    uint8(totalLength div 256), uint8(totalLength mod 256),       # Total length bytes
    0x30'u8, 0x82,                                    # Sequence, long form
    uint8(sequenceLength div 256), uint8(sequenceLength mod 256), # Sequence length bytes
    0xa2'u8, 0x82,                                    # Token, long form
    uint8(tokenLength div 256), uint8(tokenLength mod 256),       # Token length bytes
    0x04'u8, 0x82,                                    # Octet string, long form
    uint8(octetStringLength div 256), uint8(octetStringLength mod 256)  # String length bytes
    ]
    token.add(ntlmMsg)
    return token
  return @[]