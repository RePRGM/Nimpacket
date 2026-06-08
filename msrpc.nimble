# Package
version       = "0.2.0"
author        = "msrpc-nim contributors"
description   = "Cross-platform MS-RPC + SMB2 + NTLM + NDR + LDAP/CLDAP in pure Nim"
license       = "MIT"
srcDir        = "src"
installExt    = @["nim"]
skipDirs      = @["tests", "examples"]
bin           = @["msrpc/repl", "msrpc/idlgen/cli"]
binDir        = "build"
namedBin      = {
  "msrpc/repl":       "msrpc-repl",
  "msrpc/idlgen/cli": "msrpc-idlgen"
}.toTable

# Dependencies — zero external deps. All crypto is pure-Nim.
requires "nim >= 2.0.0"

# --- Tasks ----------------------------------------------------------

task test, "Unit + integration loopback tests":
  exec "nim r --hints:off --threads:on tests/all.nim"

task test_unit, "Unit tests only (no threading needed)":
  exec "nim r --hints:off tests/unit_all.nim"

task test_live, "Live tests against a real DC (env-gated)":
  exec "nim r --hints:off -d:msrpcLive tests/live/all.nim"

task docs, "Generate API docs into docs/":
  exec "nim doc --project --outdir:docs src/msrpc.nim"

task examples, "Build the bundled example tools":
  for ex in @["lsadom", "lsausers", "samrenum", "sctl", "netshares",
              "ldapquery", "cldapquery", "dcping"]:
    exec "nim c -o:build/" & ex & " --hints:off --path:src examples/" & ex & ".nim"
