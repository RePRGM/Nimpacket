import std/unittest
import msrpc/common/[buffers, guid]
import msrpc/rpc/epm

const RaaUuid = "0b1c2170-5732-4e0e-8cd3-d9b16f3b84d7"
const NdrUuid = "8a885d04-1ceb-11c9-9fe8-08002b104860"

suite "epm tower construction":
  test "5-floor tower has expected num_floors byte":
    let t = buildTower(parseUuid(RaaUuid), 0,
                       parseUuid(NdrUuid), 2,
                       endpoint = 49152, ip = 0)
    check t[0] == 5'u8
    check t[1] == 0'u8

  test "TCP port (big-endian) round-trips":
    let t = buildTower(parseUuid(RaaUuid), 0,
                       parseUuid(NdrUuid), 2,
                       endpoint = 49152, ip = 0x7f000001'u32)
    check parseTcpPortFromTower(t) == 49152'u16

  test "TCP port 0 still parses":
    let t = buildTower(parseUuid(RaaUuid), 0, parseUuid(NdrUuid), 2,
                       endpoint = 0, ip = 0)
    check parseTcpPortFromTower(t) == 0

suite "ept_map encoder":
  test "IN params have correct prologue":
    let stub = buildEptMapStub(parseUuid(RaaUuid), 0, parseUuid(NdrUuid),
                                maxTowers = 4)
    # First 4 bytes: obj referent id (null)
    check stub[0..3] == @[0'u8, 0, 0, 0]
    # Next 4: map_tower referent id (0x00020000 LE)
    check stub[4..7] == @[0'u8, 0, 2, 0]
    # tower_len conformance count + tower_length should match
    let towerLen =
      uint32(stub[8]) or
      (uint32(stub[9]) shl 8) or
      (uint32(stub[10]) shl 16) or
      (uint32(stub[11]) shl 24)
    let towerLen2 =
      uint32(stub[12]) or
      (uint32(stub[13]) shl 8) or
      (uint32(stub[14]) shl 16) or
      (uint32(stub[15]) shl 24)
    check towerLen == towerLen2
    check towerLen > 0
    # max_towers at the very end
    check stub[^4..^1] == @[4'u8, 0, 0, 0]

  test "parseEptMapReply pulls towers out of a synthetic reply":
    # Build a synthetic OUT-direction NDR matching the wire layout:
    # entry_handle(20) + num_towers(4) + max_count(4) + offset(4) +
    # actual(4) + refid(4) + maxlen(4) + towerLen(4) + tower bytes
    let tower = buildTower(parseUuid(RaaUuid), 0, parseUuid(NdrUuid), 2,
                            endpoint = 49152, ip = 0)
    let b = newBuffer()
    for _ in 0 ..< 20: b.writeByte(0)   # entry_handle zeros
    b.writeBytes([1'u8, 0, 0, 0])        # num_towers = 1
    b.writeBytes([1'u8, 0, 0, 0])        # max_count
    b.writeBytes([0'u8, 0, 0, 0])        # offset
    b.writeBytes([1'u8, 0, 0, 0])        # actual
    b.writeBytes([0'u8, 0, 2, 0])        # refid (non-null)
    b.writeBytes([byte(tower.len), 0, 0, 0])    # max_count
    b.writeBytes([byte(tower.len), 0, 0, 0])    # tower_length
    b.writeBytes(tower)

    let towers = parseEptMapReply(b.consumed)
    check towers.len == 1
    check parseTcpPortFromTower(towers[0]) == 49152'u16
