# Contributing

Welcoming PRs that:

- Add coverage for additional MS-* protocols. See "Adding a new
  protocol" in `README.md`. High-value next targets: MS-RRP
  (remote registry), MS-TSCH (task scheduler), MS-EVEN6 (event log),
  MS-NRPC (full Netlogon RPC, not just CLDAP discovery), MS-DRSR
  (directory replication).
- Fill in NDR coverage gaps (multi-dim arrays, more union flavors).
- Add a Kerberos auth provider behind the existing `AuthProvider` SPI.
- Improve the IDL → Nim generator. Highest-leverage frontier: switched
  unions, sized conformant arrays with deferred bodies, unique
  pointer-to-string. Each one knocked out makes another whole
  protocol nearly free.
- Add LDAP enhancements: paged search (RFC 2696), extensible match
  filters, StartTLS, SASL bind via GSSAPI.
- Add SMB3 dialects (3.0 / 3.0.2 / 3.1.1) with encryption (AES-CCM /
  AES-GCM).
- Find more "going live found this" bugs against a real Windows host
  and capture them in `README.md`'s bug-fix table.

Style notes:

- Code comments answer "why" not "what". Names already say what.
- Spec references in comments use the canonical form: `MS-NLMP §3.4.5.2`.
- Tests prefer spec test vectors over hand-rolled values when the spec
  provides them. When it doesn't, prefer round-trip + boundary tests.
- Live tests must be env-gated; `nimble test` must never need network.

Before pushing:

```
nimble test          # unit + integration loopback
```

If you have a Windows / Samba target reachable:

```
MSRPC_TEST_HOST=...  \
MSRPC_TEST_USER=...  \
MSRPC_TEST_PASS='..' \
MSRPC_TEST_DOMAIN=.. \
nimble test_live
```
