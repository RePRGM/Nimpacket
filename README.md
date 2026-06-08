# msrpc-nim

A cross-platform, pure-Nim implementation of the Microsoft network
protocol stack. Talks to Windows servers (and Samba) from Linux —
or macOS, or anywhere Nim runs — with no SSPI, libsmbclient, or
impacket dependency. Every layer from byte buffers up to the
protocol-specific opnums is implemented in Nim itself.

```
              ┌───────────────────────────────────────────────┐
   proto/     │  MS-RAA   MS-SAMR   MS-LSARPC   MS-SCMR       │
              │  MS-SRVS  +  your own RPC protocol            │
              │                                               │
   ldap/      │  LDAP (TCP) + CLDAP (UDP)                     │
              ├───────────────────────────────────────────────┤
   rpc/       │  client (BIND, AUTH3, REQUEST/RESPONSE, EPM)  │
              │  fragment ─ wrapper (sec_trailer placement)   │
              │  transport (TCP, SMB-named-pipe)              │
              ├──────────────────┬─────────────┬──────────────┤
   auth/      │  NTLM (NTOWFv2,  │  SPNEGO     │  Kerberos    │
              │   messages,      │  (DER,      │  (AS, TGS,   │
              │   session, MIC)  │  GSS wrap,  │  AP-REQ,     │
              │                  │  NegToken*) │  RC4 + AES)  │
              ├──────────────────┴─────────────┴──────────────┤
   smb/       │  SMB2 (negotiate, session_setup, tree_connect,│
              │   create, read, write, IOCTL TRANSCEIVE) +    │
              │  SMB3 (3.0 / 3.0.2 / 3.1.1 negotiate, AES-    │
              │   CMAC signing, AES-CCM transparent encrypt)  │
              ├───────────────────────────────────────────────┤
   ndr/       │  NDR3 + NDR64 (primitives, arrays, strings,   │
              │   pointers, deferred queue, unions, structs)  │
              ├───────────────────────────────────────────────┤
   crypto/    │  MD4, MD5, HMAC-MD5, RC4, CSPRNG,             │
              │  SHA-1, SHA-256, HMAC-SHA1/256,               │
              │  AES-128/256, AES-CMAC, AES-CCM,              │
              │  PBKDF2, SP 800-108 KBKDF       (pure Nim)    │
              ├───────────────────────────────────────────────┤
   common/    │  buffers, endian, UUID, SID, NTSTATUS, UTF-16 │
              └───────────────────────────────────────────────┘
                ┌─────────────────────────────────────┐
   idlgen/      │  MIDL .idl → Nim stub generator    │
                └─────────────────────────────────────┘
```

## Status

- **Validated live against real Windows and Samba** — every byte format
  this library produces has been round-tripped through Microsoft's
  actual RPC + SMB stack at least once.
- **Validated against MS-NLMP §4.2 spec vectors** — NTOWFv2,
  NtChallengeResponse, SessionBaseKey, EncryptedRandomSessionKey,
  signing & sealing keys all match the worked-example bytes bit-exact.
- **Validated against impacket** — for cases where credentials
  prevented success, my code's responses are byte-identical to
  impacket's against the same server.
- **Validated against RFC 3961 + RFC 3962 vectors** — n-fold,
  PBKDF2-HMAC-SHA1, and the AES-128/256 stringToKey worked examples
  all match bit-exact.
- **248 tests passing**: ~241 unit, 4 loopback integration (TCP, NTLM
  sign+seal, fragmentation, UDP CLDAP), 3 live env-gated.
- **Structure-aware fuzzer.** DER/NTLM/SMB2/DCE-RPC/LDAP/Kerberos
  generators; ~1.6M iterations in 30s with 0 crashes across 19
  decoder targets.
- **Zero external dependencies.** Pure-Nim crypto, pure-Nim DER/BER,
  pure-Nim everything.

## Quickstart

```bash
git clone https://github.com/RePRGM/Nimpacket
cd Nimpacket
nimble test                              # unit + loopback suite

# Property fuzzer (default 2s budget; raise via env):
MSRPC_FUZZ_BUDGET_MS=30000 nim r --path:src tests/fuzz/fuzz_runner.nim

# Live test against a real Windows host:
MSRPC_TEST_HOST=10.0.0.5                 \
MSRPC_TEST_USER=alice                    \
MSRPC_TEST_PASS='<password>'             \
MSRPC_TEST_DOMAIN=CORP                   \
nimble test_live
```

## Tools shipped in the box

| Tool | What it does | Underlying protocol |
|---|---|---|
| `examples/lsadom.nim`   | Print the target host's local SAM domain SID | LSARPC |
| `examples/lsausers.nim` | Enumerate local Windows users by SID lookup  | LSARPC |
| `examples/samrenum.nim` | Enumerate SAM domains + users (admin-only)   | SAMR |
| `examples/sctl.nim`     | Query / enumerate Windows services           | SCMR |
| `examples/netshares.nim`| List shares on a host (`net view \\host`)   | SRVS |
| `examples/ldapquery.nim`| Search a directory server via LDAP/TCP       | LDAP |
| `examples/cldapquery.nim`| Arbitrary CLDAP query via UDP/389           | CLDAP |
| `examples/dcping.nim`   | AD DC discovery (`nltest /dsgetdc:`)         | CLDAP |
| `src/msrpc/repl.nim`    | Interactive `rpcclient`-style shell          | LSARPC, SAMR |
| `src/msrpc/idlgen/cli.nim` | MIDL `.idl` → Nim stub generator         | — |

Build them with `nim c -o:<name> --path:src <path>.nim` and run, or
let `nimble examples` build the lot into `build/`.

## Using the library in your own code

A full guide — high-level "it just works" patterns, mid-level
composition, low-level primitives, plus the *why* behind each layer —
lives in [`USAGE.md`](USAGE.md). The snippets below are the
five-minute version.

```nim
import msrpc/common/[guid, sid, status]
import msrpc/auth/ntlm/provider
import msrpc/smb/client as smb
import msrpc/rpc/[client, transport_np]
import msrpc/proto/lsarpc/idl

let smbAuth = newNtlmProvider("CORP", "alice", "<password>", "myhost")
let smbSession = newSmbSession("dc01.corp", 445, smbAuth, "cifs/dc01.corp")
let pipe = smbSession.openPipe("lsarpc")
let rpc = connect(newNamedPipeTransport(pipe),
                  parseUuid(LsarInterfaceUuid), 0)
var pol: LsarHandle
discard rpc.lsarOpenPolicy2("",
  POLICY_VIEW_LOCAL_INFORMATION or POLICY_LOOKUP_NAMES, pol)
var info: PolicyAccountDomainInfo
discard rpc.lsarQueryAccountDomain(pol, info)
echo "domain: ", info.domainName, "  sid: ", info.domainSid
```

LDAP / CLDAP usage:

```nim
import msrpc/ldap/[messages, client, cldap]

# TCP LDAP
let l = newLdapClient("ldap.example.com", 389)
let b = l.bindSimple("cn=alice,dc=example,dc=com", "secret")
let r = l.search("dc=example,dc=com", lsWholeSubtree,
                 filter = buildEqualityFilter("uid", cast[seq[byte]](@"bob")),
                 attributes = @["cn", "mail"])
for e in r.entries: echo e.dn

# CLDAP (UDP)
let c = newCldapClient("dc01.corp.example", timeoutMs = 2000)
let s = c.cldapSearch(baseDn = "", scope = lsBaseObject,
                       filter = buildPresenceFilter("objectClass"),
                       attributes = @["namingContexts", "currentTime"])
for e in s.entries: echo e.attributes

# AD DC discovery (one-call helper around CLDAP)
let dc = cldapNetlogonPing("dc01.corp.example", dnsDomain = "corp.example")
echo "Forest=", dc.dnsForest, "  Site=", dc.dcSiteName, "  Flags=", dc.flags
```

## Adding a new protocol

The fast path:

1. Find the protocol's `.idl` in
   [Microsoft Open Specifications](https://learn.microsoft.com/openspecs/windows_protocols/).
2. Save the type + interface block to a `.idl` file.
3. Run `idlgen path/to/proto.idl -o src/msrpc/proto/myproto/idl.nim`.
4. Edit the generated marshallers for the tricky bits (unique strings,
   conformant arrays with explicit `size_is`, switched unions).
5. Add a unit test that round-trips bytes via `ndrEncode` / `ndrDecode`.

The slow path:

1. Hand-write `proto/myproto/types.nim` with the structs.
2. Hand-write `proto/myproto/idl.nim` with `marshal` procs for each
   type and a thin wrapper for each opnum.
3. Use `rpc/client.RpcClient.call` to send the call.

Either way, look at `proto/lsarpc/` or `proto/scmr/` for worked
examples — `lsarpc` covers everything from `LsarOpenPolicy2` through
`LsarLookupSids` with the full `LSAPR_REFERENCED_DOMAIN_LIST` /
`LSAPR_TRANSLATED_NAMES` decode pipeline. `scmr` shows the
`top-level ref pointer = no referent id on wire` pattern.

## Architecture notes

- **NDR3 + NDR64 share code.** Every `marshal` proc inspects its
  `NdrContext.syntax` field and emits NDR3 (4-byte counts) or NDR64
  (8-byte counts) accordingly. The deferred-pointer queue lives on
  the context.
- **Encoder and decoder are the same proc.** `marshal(c, v)` reads
  `c.dir` and either writes to `c.buf` or reads from it. The same
  type definition serves both directions.
- **Transports are interface-typed.** Drop in a new transport by
  subclassing `rpc.Transport`. The TCP and named-pipe transports
  both satisfy the same shape.
- **AuthProvider is virtual.** NTLM, SPNEGO, and Kerberos all ship and
  implement the same `initialize` / `step` interface, so any of them
  drops into the same RPC/SMB call sites. SPNEGO can carry either NTLM
  or Kerberos as its inner mech.
- **Sign+seal piggy-backs on session state.** `NtlmProvider.role`
  selects client-to-server or server-to-client key direction so the
  same provider can be the client peer or the server peer.
- **LDAP and DCE-RPC share their ASN.1.** The DER encoder built for
  SPNEGO is the basis of both. `auth/spnego/asn1.nim` is the canonical
  source; `ldap/ber.nim` extends it with integer/boolean/enumerated
  helpers.
- **CLDAP is general-purpose.** `CldapClient` + `cldapSearch` issues
  any LDAP Search over UDP. `cldapNetlogonPing` is a thin wrapper for
  the AD-discovery use case that builds the well-known filter and
  decodes the binary `netlogon` attribute.

## Bug fixes found by running live

| # | Bug | How surfaced |
|---|---|---|
| 1 | EPM tower's TCP floor protocol byte should be `0x07`, not `0x0A` | All `ept_map` queries returned `EPT_S_NOT_REGISTERED` |
| 2 | NTLMv2 response must echo server `MsvAvTimestamp`, not local time | Auth flakiness across clock skew |
| 3 | SMB2 CREATE has no inline `Buffer` placeholder byte; `NameOffset = 64 + 56` | First pipe open failed with `STATUS_INVALID_PARAMETER` |
| 4 | RPC over named pipe needs `FSCTL_PIPE_TRANSCEIVE`, not separate WRITE+READ | Server closed pipe after first BIND |
| 5 | AUTH3 must go out via one-way SMB WRITE, not TRANSCEIVE | First sealed REQUEST got `STATUS_PIPE_BUSY` |
| 6 | `STATUS_PENDING` IOCTL response uses ERROR body format, not IOCTL body | Off-by-some buffer overrun |
| 7 | NTLM anonymous wire form: strip `NEGOTIATE_VERSION` and `NEGOTIATE_ANONYMOUS` from AUTHENTICATE flags | Server rejected with `STATUS_INVALID_PARAMETER` |
| 8 | `LSAPR_TRANSLATED_NAME` needs `alignTo(4)` after `SID_NAME_USE` u16 (the embedded `RPC_UNICODE_STRING` forces 4-alignment) | Mid-decode buffer overrun |
| 9 | AUTHENTICATE MIC offset depends on whether the `NEGOTIATE_VERSION` flag is *set* (not on the build-time `hasVersion` bool) | MIC patched at wrong offset |
| 10 | Top-level ref pointers (MIDL `[in,string] T *`) emit **no** referent id on the wire — only top-level unique pointers do (C706 §14.3.10) | `ROpenServiceW` returned a 0x1783 fault until the bogus refid was dropped |
| 11 | `parseBindAckBody` cast a raw `u16` straight to a 3-value enum, raising `RangeDefect` on any other value | Surfaced by structure-aware fuzzing with a valid RPC PDU prefix — replaced with an explicit range check that raises `ValueError` |
| 12 | AES-CTS (RFC 3962 §5) wire format is `... \|\| full Cn (16) \|\| truncated Cn-1 (d)`, not the other way around; the high bytes of Cn-1 are recovered via `AES⁻¹(Cn)[d..15] = Cn-1[d..15]` thanks to the zero-padding invariant | First AES round-trip failed; only caught by writing round-trip tests at the lowest layer instead of trusting the spec's prose |

## Status of MS-* coverage

| Spec | Coverage |
|---|---|
| MS-NLMP (NTLM) | NTOWFv1, NTOWFv2, all three messages, sign+seal, MIC, anonymous, client and server roles |
| MS-SPNG (SPNEGO) | DER encoder, GSS-API wrap, `NegTokenInit` / `NegTokenResp`, NTLM or Kerberos inner mech |
| MS-KILE / RFC 4120 (Kerberos) | AS-REQ → AS-REP (with `PA-ENC-TIMESTAMP` retry on `KDC_ERR_PREAUTH_REQUIRED`), TGS-REQ → TGS-REP, AP-REQ + Authenticator, GSS-API token wrap (RFC 4121 init token) |
| RFC 4757 (RC4-HMAC ETYPE 23) | string-to-key, K1/K2/K3 derivation, encrypt + decrypt for usages 1/3/8/11 |
| RFC 3961 / RFC 3962 (AES ETYPEs 17/18) | n-fold, DR/DK, PBKDF2-HMAC-SHA1, full `stringToKey` with `DK(tkey, "kerberos")`, AES-CTS (CS3), AES-CTS-HMAC-SHA1-96 profile with confounder + integrity check |
| MS-RPCE (DCE-RPC) | Connection-oriented: BIND, BIND_ACK, AUTH3, REQUEST, RESPONSE, FAULT, fragmentation |
| C706 NDR / MS-RPCE §2.2.5 NDR64 | All primitives + array variants + pointers + unions + strings |
| MS-SMB2 | NEGOTIATE (dialects 2.0.2, 2.1, 3.0, 3.0.2, 3.1.1 with preauth-integrity + AES-CCM-128 negotiate contexts), SESSION_SETUP, TREE_CONNECT, CREATE, READ, WRITE, IOCTL, CLOSE; SMB 3.0/3.0.2 per-message AES-CMAC signing and AES-CCM-128 transparent encryption via `TRANSFORM_HEADER` |
| MS-LSAD / MS-LSAT | `LsarOpenPolicy2`, `LsarClose`, `LsarQueryInformationPolicy` (AccountDomain), `LsarLookupSids` |
| MS-SAMR | `SamrConnect`, `SamrConnect5`, `SamrCloseHandle`, `SamrLookupDomainInSamServer`, `SamrEnumerateDomainsInSamServer`, `SamrOpenDomain`, `SamrEnumerateUsersInDomain` |
| MS-RAA | All five opnums (FreeContext, InitializeContextFromSid, AccessCheck, GetInformationFromContext) |
| MS-SCMR | `RCloseServiceHandle`, `RControlService`, `RQueryServiceStatus`, `REnumServicesStatusW`, `ROpenSCManagerW`, `ROpenServiceW` |
| MS-SRVS | `NetrShareEnum` level 1 |
| MS-NRPC | `NETLOGON_SAM_LOGON_RESPONSE_EX` decoding (read-only) |
| EPM | Full `ept_map` round-trip; tower builder for `ncacn_ip_tcp` |
| RFC 4511 LDAP | BindRequest (simple), UnbindRequest, SearchRequest with arbitrary filters, BindResponse / SearchResultEntry / SearchResultDone parsing |
| RFC 1798 CLDAP | Generic `cldapSearch` over UDP/389 + AD `netlogon` discovery |

## License

MIT. See `LICENSE`.
