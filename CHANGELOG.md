# Changelog

## 0.2.0 — 2026-06-08

**Protocols added:**
- MS-SCMR (Service Control Manager): `ROpenSCManagerW`, `ROpenServiceW`,
  `RCloseServiceHandle`, `RQueryServiceStatus`, `RControlService`,
  `REnumServicesStatusW`. Tool: `sctl`.
- MS-SRVS (Server Service): `NetrShareEnum` level 1. Tool: `netshares`.
- RFC 4511 LDAP over TCP: BindRequest (simple), UnbindRequest,
  SearchRequest with arbitrary filter trees, BindResponse /
  SearchResultEntry / SearchResultDone. Tool: `ldapquery`.
- RFC 1798 CLDAP over UDP: generic `CldapClient` + `cldapSearch`
  with std/selectors-based timeouts, plus `cldapNetlogonPing`
  for AD DC discovery. Decodes `NETLOGON_SAM_LOGON_RESPONSE_EX`
  with DNS-compressed name resolution. Tools: `cldapquery`, `dcping`.

**Bug fix found live:**
- #10 — top-level ref pointers (MIDL `[in,string] T *`) emit no
  referent id on the wire; only top-level unique pointers do.
  C706 §14.3.10. Surfaced as `ROpenServiceW` 0x1783 faults.

**Test coverage:**
- 204 tests passing (197 unit / 4 loopback / 3 live)
- New: UDP CLDAP loopback test via local mock server
- New: SCMR, SRVS, LDAP, CLDAP byte-layout unit tests

**Live validations against Windows 10:**
- SCMR `status RpcSs` / `Spooler` / `Dnscache` — all return RUNNING
  with correct service-type bits.
- SRVS `NetrShareEnum` — returns ADMIN$, C$, IPC$, plus user shares
  (matches `net view \\host` exactly).

## 0.1.0 — initial release

First working release. The library can:

- Speak DCE-RPC connection-oriented over TCP and over SMB2 named pipes
- Authenticate with NTLMv2 (sign-only or sign+seal), with optional MIC
  and SPNEGO wrapping
- Resolve services via the endpoint mapper
- Marshal both NDR3 and NDR64

Protocols shipped: MS-LSAT/MS-LSAD, MS-SAMR, MS-RAA.

Tools shipped: `lsadom`, `lsausers`, `samrenum`, `msrpc-repl`, `idlgen`.

Test coverage: 165+ unit tests, 3 integration loopback tests, Tier C
live tests against real Windows.
