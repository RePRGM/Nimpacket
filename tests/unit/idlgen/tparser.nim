import std/[unittest, strutils]
import msrpc/idlgen/[parser, ast]

suite "idl parser":
  test "minimal interface with one method":
    let src = """
      [uuid(12345778-1234-abcd-ef00-0123456789ab), version(1.0)]
      interface samr {
        NTSTATUS SamrCloseHandle(
          [in, out] SAMPR_HANDLE *SamHandle);
      }
    """
    let p = newParser(src)
    let ifaces = p.parseIdl()
    check ifaces.len == 1
    check ifaces[0].name == "samr"
    check ifaces[0].methods.len == 1
    check ifaces[0].methods[0].name == "SamrCloseHandle"
    check ifaces[0].methods[0].params.len == 1

  test "interface attrs extracted":
    let src = """
      [uuid(0b1c2170-5732-4e0e-8cd3-d9b16f3b84d7), version(0.0)]
      interface raa { void Stub(); }
    """
    let p = newParser(src)
    let ifaces = p.parseIdl()
    check hasAttr(ifaces[0].attrs, aUuid)
    check hasAttr(ifaces[0].attrs, aVersion)
    let u = getAttr(ifaces[0].attrs, aUuid)
    check u.args[0] == "0b1c2170-5732-4e0e-8cd3-d9b16f3b84d7"

  test "typedef struct picked up":
    let src = """
      interface foo {
        typedef struct {
          DWORD Length;
          [size_is(Length)] byte *Data;
        } BLOB;
      }
    """
    let p = newParser(src)
    let ifaces = p.parseIdl()
    check ifaces[0].structs.len == 1
    check ifaces[0].structs[0].name == "BLOB"
    check ifaces[0].structs[0].fields.len == 2

  test "opnums are sequential":
    let src = """
      interface bar {
        void A();
        void B();
        void C();
      }
    """
    let p = newParser(src)
    let ifaces = p.parseIdl()
    check ifaces[0].methods[0].opnum == 0
    check ifaces[0].methods[1].opnum == 1
    check ifaces[0].methods[2].opnum == 2

  test "attribute argument parsing":
    let src = """
      interface i {
        void F([in, size_is(Count)] byte *Buf, [in] DWORD Count);
      }
    """
    let p = newParser(src)
    let ifaces = p.parseIdl()
    let m = ifaces[0].methods[0]
    check m.params.len == 2
    let buf = m.params[0]
    check hasAttr(buf.attrs, aSizeIs)
    check getAttr(buf.attrs, aSizeIs).args == @["Count"]
