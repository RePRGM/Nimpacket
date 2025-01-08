type  
  absSyntaxID* = object
    ifUUID*: array[16, uint8]
    ifVersion*: uint16
    ifMinorVersion*: uint16

  presContextElement* = object
    contextID*: uint16
    numTransSyntaxes*: uint8
    padding*: uint8
    absSyntax*: absSyntaxID
    transSyntax*: absSyntaxID

  PDUHeader* = object
    version*: uint8
    minorVersion*: uint8
    pType*: uint8
    pFlags*: uint8
    dRep*: array[4, uint8]
    fragLength*: uint16
    authLength*: uint16
    callID*: uint32

  PDUBind* = object
    header*: PDUHeader
    maxXmitFrag*: uint16
    maxRecvFrag*: uint16
    assocGroupID*: uint32
    numContextElements*: uint8

  PDURequest* = object
    header*: PDUHeader
    allocHint*: uint32
    contextID*: uint16
    opNum*: uint16