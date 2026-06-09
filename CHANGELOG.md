# Changelog

## 0.4.0 — 2026-06-08

Promotes the Kerberos work that was "staged for 0.4" in 0.3.0 to a real
release: the full AS/TGS/AP-REQ exchange now runs end to end and can sign,
seal, and wrap live RPC traffic.

**Kerberos transport + GSS:**
- TCP/88 KDC transport with 4-byte length prefix and auto-fallback from
  UDP/88 (`KRB5KRB_ERR_RESPONSE_TOO_BIG` and oversized-datagram policy)
- RFC 4121 GSS-API per-message tokens: `GSS_Wrap` / `GSS_Unwrap` / `GSS_GetMIC`
  with the AES-CTS-HMAC-SHA1-96 confidentiality + integrity profile
- MS-KILE `GSS_WrapEx` for DCE-RPC `RPC_C_AUTHN_LEVEL_PKT_PRIVACY` sealing
- RC4-HMAC (ETYPE 23) GSS wrap/unseal + MIC for RC4 sessions
- Generic RPC sign/seal path wired through the `AuthProvider` SPI for Kerberos
- Windows `setsockopt` handling for the raw KDC sockets

**Tooling / tests:**
- In-process **mock KDC** (`mockkdc.nim`) that mints AS/TGS replies and
  service tickets for fully offline Kerberos unit + integration tests
- PDU **pretty-printer** and **byte-diff** helpers for wire debugging

## 0.3.0 — 2026-06-08

**Crypto foundation:**
- SHA-1 + HMAC-SHA-1 (FIPS 180-4, RFC 2202 vectors pass)
- SHA-256 + HMAC-SHA-256 (FIPS 180-4, RFC 4231 vectors pass)
- AES-128 + AES-256 core (FIPS 197 Appendix B/C vectors pass)
- AES-CMAC (RFC 4493 §4 vectors pass — empty / 16 / 40 / 64 byte
  messages)
- AES-CCM authenticated encryption (RFC 3610 Packet Vector #1
  passes, including round-trip + tamper detection)
- PBKDF2-HMAC-SHA1 (RFC 6070 vectors pass)
- SP 800-108 counter-mode KBKDF (for SMB3 session-key derivation)

**SMB3 (dialect 3.0 / 3.0.2 / 3.1.1) — bytes-on-wire correct:**
- Negotiate context layout for `PreauthIntegrity` + `Encryption`
- SMB 3.0 key derivation (SigningKey / EncryptionKey / DecryptionKey
  / ApplicationKey via SP 800-108 with documented labels and contexts)
- SMB 3.1.1 key derivation (uses running pre-auth SHA-512 hash as
  context)
- Per-message AES-CMAC signing (replaces 2.x HMAC-SHA-256)
- Transform-header encryption via AES-128-CCM with 11-byte nonce and
  16-byte tag (round-trip + tamper detection in unit tests)

**Kerberos foundations:**
- KRB5 ASN.1 message structures (subset for AS-REQ + KRB-ERROR)
- RFC 3962 string-to-key (PBKDF2-HMAC-SHA1) for ETYPEs 17/18
- AES-CTS-HMAC-SHA1-96 encryption (RFC 3962 §5)
- AS-REQ builder
- KRB-ERROR parser
- KDC UDP transport
- `KerberosProvider` skeleton fitting the existing `AuthProvider` SPI
  (full AS exchange + TGS-REQ + AP-REQ is staged for 0.4)

**Fuzzing harness:**
- `nimble fuzz` runs a property fuzzer across 13 decoders
- Time-budgeted via `MSRPC_FUZZ_BUDGET_MS`, reproducible via
  `MSRPC_FUZZ_SEED`
- Catches `Defect`-raising paths that wouldn't surface in unit tests
- **Found 4 real bugs on first run:**
  - PDU header: out-of-range `PduType` cast → unrecoverable
    `RangeDefect`. Now raises `ValueError` instead.
  - NTLM AV_PAIRs: out-of-range `AvId` cast on garbage trailing
    bytes. Now skips unknown pair IDs.
  - SMB2 header: `doAssert` on bad signature → uncatchable. Now
    raises `ValueError`.
  - Same `AvId` issue surfaced in BIND_ACK parser path.

**Test coverage:**
- 248 tests passing across 80 suites
- New: SHA1/256, HMAC-SHA1/256, AES-128/256, AES-CMAC, AES-CCM,
  PBKDF2, KBKDF, SMB3 round-trip, Kerberos ETYPE + ASN.1

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
