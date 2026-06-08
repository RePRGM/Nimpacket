## rpc/epm.nim — endpoint-mapper client (MS-RPCE §3.1.2.5 ept_map).
##
## The endpoint mapper runs on TCP/135 (well-known) and translates an
## interface UUID/version into a transport-specific endpoint (TCP port
## for ncacn_ip_tcp, pipe name for ncacn_np).
##
## Interface info:
##   uuid    e1af8308-5d1f-11c9-91a4-08002b14a0fa
##   version 3.0
##   opnum 3  ept_map
##
## ``ept_map`` takes a "tower" (a stack of protocol identifiers ending
## with the abstract interface UUID) and returns matching towers. For
## the ncacn_ip_tcp case the returned tower contains the resolved port.
##
## Tower layout (MS-RPCE Appendix B):
##   u16 num_floors
##   floors[num_floors]:
##     u16 lhs_len; lhs_len bytes;
##     u16 rhs_len; rhs_len bytes;
##
## Floor 1: 0x0d, UUID16, version u16 — abstract interface
## Floor 2: 0x0d, UUID16 (NDR), version u16 — transfer syntax
## Floor 3: 0x0a — ncacn_ip_tcp; rhs = endpoint port (u16 BE)
## Floor 4: 0x09 — IP address; rhs = u32 BE
##
## This module exposes only what's needed for v0: look up a TCP port
## for a given interface UUID, on a given EPM host.

import ../common/[buffers, endian, guid]

const EpmInterfaceUuid* = "e1af8308-5d1f-11c9-91a4-08002b14a0fa"
const EpmInterfaceMajor* = 3'u16
const EpmInterfaceMinor* = 0'u16
const EpmPort* = 135

const
  FloorUuid*    = 0x0d'u8
  FloorDcerpc*  = 0x0b'u8   ## RPC connection-oriented protocol identifier
  FloorTcp*     = 0x07'u8   ## ncacn_ip_tcp (per impacket/Samba; C706 §L is ambiguous)
  FloorIp*      = 0x09'u8

# --- tower construction ------------------------------------------------

proc buildTower*(interfaceUuid: Uuid; interfaceVer: uint16;
                 ndrUuid: Uuid; ndrVer: uint16 = 2'u16;
                 endpoint: uint16 = 0; ip: uint32 = 0): seq[byte] =
  ## Build a 5-floor tower for ncacn_ip_tcp.
  let b = newBuffer()
  b.writeU16LE(5)              # num_floors

  proc floor(lhs, rhs: openArray[byte]) =
    b.writeU16LE(uint16(lhs.len))
    b.writeBytes(lhs)
    b.writeU16LE(uint16(rhs.len))
    b.writeBytes(rhs)

  # Floor 1: abstract interface uuid
  var lhs1 = newSeq[byte](19)
  lhs1[0] = FloorUuid
  for i, x in interfaceUuid.toWire: lhs1[1 + i] = x
  lhs1[17] = byte(interfaceVer and 0xff)
  lhs1[18] = byte((interfaceVer shr 8) and 0xff)
  let rhs1 = @[0'u8, 0]   # version_minor u16
  floor(lhs1, rhs1)

  # Floor 2: NDR transfer syntax uuid
  var lhs2 = newSeq[byte](19)
  lhs2[0] = FloorUuid
  for i, x in ndrUuid.toWire: lhs2[1 + i] = x
  lhs2[17] = byte(ndrVer and 0xff)
  lhs2[18] = byte((ndrVer shr 8) and 0xff)
  floor(lhs2, @[0'u8, 0])

  # Floor 3: RPC connection-oriented protocol
  floor(@[FloorDcerpc], @[0'u8, 0])

  # Floor 4: ncacn_ip_tcp port
  floor(@[FloorTcp], @[byte((endpoint shr 8) and 0xff), byte(endpoint and 0xff)])

  # Floor 5: IP address (BE u32)
  let ipBytes = @[byte((ip shr 24) and 0xff'u32),
                  byte((ip shr 16) and 0xff'u32),
                  byte((ip shr  8) and 0xff'u32),
                  byte(ip and 0xff'u32)]
  floor(@[FloorIp], ipBytes)

  result = b.consumed

proc parseTcpPortFromTower*(tower: openArray[byte]): uint16 =
  ## Pull out the TCP port from floor 4 of a returned tower.
  let b = newBuffer(@tower)
  let n = b.readU16LE()
  for i in 1 .. int(n):
    let lhsLen = b.readU16LE()
    let lhs = b.readBytes(int(lhsLen))
    let rhsLen = b.readU16LE()
    let rhs = b.readBytes(int(rhsLen))
    if lhs.len >= 1 and lhs[0] == FloorTcp and rhs.len >= 2:
      # Port is BE u16 in the rhs.
      return (uint16(rhs[0]) shl 8) or uint16(rhs[1])
  raise newException(ValueError, "tower has no TCP floor")

# --- ept_map NDR encoding ----------------------------------------------
#
# IDL (C706 §3.1.2.5):
#
#   typedef struct {
#       unsigned32 tower_length;
#       [size_is(tower_length)] byte tower_octet_string[];
#   } twr_t;
#
#   typedef struct {
#       unsigned32  context_handle_attributes;
#       GUID        context_handle_uuid;
#   } ept_lookup_handle_t;
#
#   void ept_map(
#       [in]     handle_t                hEpMapper,
#       [in, unique, ptr] UUID          *obj,
#       [in, ref,    ptr] twr_t         *map_tower,
#       [in, out, ref]    ept_lookup_handle_t *entry_handle,
#       [in]     unsigned32              max_towers,
#       [out]    unsigned32             *num_towers,
#       [out, length_is(*num_towers), size_is(max_towers)]
#                twr_t                  *ITowers[],
#       [out]    error_status_t         *status);

import ../ndr/context

proc buildEptMapStub*(interfaceUuid: Uuid; interfaceVer: uint16;
                      ndrUuid: Uuid; maxTowers: uint32 = 4): seq[byte] =
  ## NDR-encoded IN parameters for ept_map.
  let tower = buildTower(interfaceUuid, interfaceVer, ndrUuid)
  let c = newNdrEncode(nsNdr)

  # obj : unique pointer to GUID — pass NULL.
  c.buf.writeU32LE(0)

  # map_tower : ref pointer to twr_t.
  c.buf.writeU32LE(0x00020000'u32)        # non-null referent id
  # twr_t with embedded conformant array — max_count goes first.
  c.buf.writeU32LE(uint32(tower.len))     # max_count of tower_octet_string
  c.buf.writeU32LE(uint32(tower.len))     # tower_length
  c.buf.writeBytes(tower)
  c.align(4)                              # pad to 4 bytes

  # entry_handle : ref pointer to ept_lookup_handle_t — pass zero handle.
  c.buf.writeU32LE(0)                     # attributes
  for _ in 0 ..< 16: c.buf.writeByte(0)   # UUID (all zeros)

  # max_towers
  c.buf.writeU32LE(maxTowers)
  result = c.finish()

proc parseEptMapReply*(reply: openArray[byte]): seq[seq[byte]] =
  ## Pull each returned tower out of the OUT-direction NDR. Returns the
  ## raw tower octets; callers can use ``parseTcpPortFromTower``.
  let dc = newNdrDecode(reply, nsNdr)
  # entry_handle (20 bytes)
  discard dc.buf.readBytes(20)
  let numTowers = dc.buf.readU32LE()
  # ITowers : conformant-varying array of unique pointer to twr_t.
  let maxCount = dc.buf.readU32LE()
  discard maxCount
  let offset = dc.buf.readU32LE()
  discard offset
  let actual = dc.buf.readU32LE()

  # Read referent ids first (NDR pointer-array pattern).
  var refIds = newSeq[uint32](int(actual))
  for i in 0 ..< int(actual):
    refIds[i] = dc.buf.readU32LE()

  result = @[]
  for i in 0 ..< int(numTowers):
    if i >= refIds.len or refIds[i] == 0:
      continue
    dc.align(4)
    let maxLen = dc.buf.readU32LE()
    discard maxLen
    let towerLen = dc.buf.readU32LE()
    let towerBytes = dc.buf.readBytes(int(towerLen))
    result.add towerBytes
    dc.align(4)

# --- high-level lookup -------------------------------------------------

import client, transport_tcp

proc epmLookupTcpPort*(host: string; interfaceUuid: Uuid;
                       interfaceVer: uint16;
                       ndrUuid: Uuid): uint16 =
  ## Connect to ``host:135``, ask the EPM for the dynamic TCP port that
  ## services ``interfaceUuid`` v``interfaceVer``, and return it.
  let t = newTcpTransport(host, EpmPort)
  let c = connect(t, parseUuid(EpmInterfaceUuid),
                  interfaceVersion = uint32(EpmInterfaceMajor))
  defer: c.close()
  let stub = buildEptMapStub(interfaceUuid, interfaceVer, ndrUuid)
  let reply = c.call(opnum = 3, stub = stub)
  let towers = parseEptMapReply(reply)
  if towers.len == 0:
    raise newException(CatchableError, "EPM returned no towers")
  result = parseTcpPortFromTower(towers[0])
