import std/[unittest, strutils]
import msrpc/idlgen/[parser, emitter]

suite "idl emitter":
  test "emits Nim type + marshal for a typedef struct":
    let src = """
      [uuid(11111111-2222-3333-4444-555555555555), version(2.0)]
      interface foo {
        typedef struct {
          DWORD Cookie;
          [unique,string] LPWSTR Name;
        } ENTRY;
      }
    """
    let p = newParser(src)
    let em = newEmitter()
    let nim = em.emitAll(p.parseIdl())
    check "type Entry* = object" in nim
    check "cookie*: uint32" in nim
    check "name*: string" in nim
    check "proc marshal*(c: NdrContext; v: var Entry) =" in nim
    check "InterfaceUuid" in nim
    check "11111111-2222-3333-4444-555555555555" in nim
    check "InterfaceMajor* = 2" in nim
    check "InterfaceMinor* = 0" in nim

  test "method stub generation":
    let src = """
      interface i {
        DWORD DoIt(
          [in] DWORD Flag,
          [out] DWORD *Result);
      }
    """
    let p = newParser(src)
    let em = newEmitter()
    let nim = em.emitAll(p.parseIdl())
    check "proc doIt*(rpc: RpcClient" in nim
    check "flag: uint32" in nim
    check "result: var ref uint32" in nim
    check "opnum = 0" in nim
