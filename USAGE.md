# Using Nimpacket

A guide to the library at three altitudes: **high** ("it just works"
calls a Windows protocol against a real DC), **mid** (compose your own
RPC opnums, talk to LDAP or CLDAP directly), and **low** (raw NDR,
crypto, ASN.1, transports). With the *why* behind each layer so you can
reason about what's happening on the wire instead of treating the library
as a black box.

This is the document to read once before writing your first integration
and again whenever something doesn't behave the way you expect.

---

## 1. Mental model

Microsoft network protocols are an onion. From the outside in:

```
  ┌──────────────────────────────────────────────────────────────┐
  │  Protocol opnum                 e.g. SamrConnect5            │
  ├──────────────────────────────────────────────────────────────┤
  │  NDR marshalling                primitives, pointers,        │
  │                                 arrays, deferred queue       │
  ├──────────────────────────────────────────────────────────────┤
  │  DCE-RPC framing                BIND / AUTH3 / REQUEST       │
  │                                 + per-message auth trailer   │
  ├──────────────────────────────────────────────────────────────┤
  │  Auth provider                  NTLM   /   SPNEGO   /        │
  │                                 Kerberos (sign+seal)         │
  ├──────────────────────────────────────────────────────────────┤
  │  Transport                      TCP   or   SMB named pipe    │
  ├──────────────────────────────────────────────────────────────┤
  │  Bytes on the wire                                           │
  └──────────────────────────────────────────────────────────────┘
```

Each layer in this library is roughly one Nim module and one folder:
`proto/`, `ndr/`, `rpc/`, `auth/`, `smb/`, `common/`. Layers don't reach
through each other — `proto/samr` only knows about `rpc.RpcClient`, not
about NTLM or TCP. That means you can swap any layer (try a Kerberos
provider instead of NTLM; try a TCP transport instead of named pipes)
without touching the layers above.

The single most-confusing thing about MS-RPC is that **the auth provider
is bidirectional and mutates between calls**. NTLM signs and seals every
RPC PDU with a per-message sequence number that increments on both
sides. If you reuse the same provider across two unrelated RPC clients,
those sequence numbers desync immediately and the server returns
`STATUS_ACCESS_DENIED`. Mental rule: **one auth provider per RPC
binding**.

The second-most-confusing thing is **NDR has two flavours, NDR3 and
NDR64, and they are not the same wire format**. Counts are 4 bytes in
NDR3 and 8 bytes in NDR64. Which one you get is negotiated at BIND time
via the transfer syntax UUID. Same Nim type definition, same `marshal`
proc, the context object remembers which flavour and emits accordingly.

---

## 2. High-level: it just works

### 2.1 Connect to a DC and run an RPC opnum

```nim
import msrpc/common/[guid, sid, status]
import msrpc/auth/ntlm/provider
import msrpc/smb/client as smb
import msrpc/rpc/[client, transport_np]
import msrpc/proto/lsarpc/idl

# One NtlmProvider per binding. "MSRPCNIM" is the workstation name we
# send in the AUTHENTICATE message — pick anything you like.
let auth = newNtlmProvider("CORP", "alice", "P@ssw0rd!", "MSRPCNIM",
                           authLevel = alPktPrivacy)

# SMB session: opens TCP/445, negotiates a dialect, authenticates,
# tree-connects to IPC$. Same provider drives all three steps.
let session = newSmbSession("dc01.corp.local", 445, auth,
                            "cifs/dc01.corp.local")

# Named pipe = the standard transport for RPC against a Windows server.
let pipe = session.openPipe("lsarpc")
let rpc = connect(newNamedPipeTransport(pipe),
                  parseUuid(LsarInterfaceUuid),
                  interfaceVersion = 0,
                  auth = auth, authLevel = alPktPrivacy,
                  targetSpn = "cifs/dc01.corp.local")

var policy: LsarHandle
discard rpc.lsarOpenPolicy2("",
  POLICY_VIEW_LOCAL_INFORMATION or POLICY_LOOKUP_NAMES, policy)
var info: PolicyAccountDomainInfo
discard rpc.lsarQueryAccountDomain(policy, info)
echo "domain: ", info.domainName, "  sid: ", info.domainSid
discard rpc.lsarClose(policy)
rpc.close()
```

That's the whole "just works" surface. Replace `proto/lsarpc/idl` with
`proto/samr/idl` (or `scmr`, `srvs`, `raa`) and you get the same shape
for a different opnum.

### 2.2 LDAP search

```nim
import msrpc/ldap/[messages, client]

let l = newLdapClient("ldap.corp.local", 389)
discard l.bindSimple("cn=alice,dc=corp,dc=local", "P@ssw0rd!")
let r = l.search(
  baseDn = "dc=corp,dc=local",
  scope = lsWholeSubtree,
  filter = buildEqualityFilter("uid", cast[seq[byte]](@"bob")),
  attributes = @["cn", "mail", "memberOf"])
for entry in r.entries:
  echo entry.dn
  for k, v in entry.attributes:
    echo "  ", k, " = ", v
discard l.unbind()
```

### 2.3 Discover a DC over UDP

```nim
import msrpc/ldap/cldap

let dc = cldapNetlogonPing("dc01.corp.local",
                           dnsDomain = "corp.local")
echo "Forest=",   dc.dnsForest,
     "  Site=",   dc.dcSiteName,
     "  Flags=0x", toHex(dc.flags, 8)
```

### 2.4 Look up an RPC endpoint via EPM

```nim
import msrpc/rpc/epm
let samrUuid = parseUuid("12345778-1234-abcd-ef00-0123456789ac")
let ndrUuid  = parseUuid("8a885d04-1ceb-11c9-9fe8-08002b104860")
let port = epmLookupTcpPort("dc01.corp.local", samrUuid, 1, ndrUuid)
echo "SAMR is on dynamic TCP port ", port
```

EPM is only useful when the server publishes its dynamic-port RPC
endpoints (Windows does; minimal Samba builds sometimes don't). For
anything mainstream — SAMR, LSARPC, SRVS, SCMR, MS-RAA — going via SMB
named pipes is more portable and works against locked-down servers that
block direct TCP RPC.

---

## 3. Choosing an auth provider

You have three options, all implementing the same `AuthProvider` SPI
(`initialize` / `step` / `sign` / `seal` / `verify` / `unseal`).

### NTLM (`msrpc/auth/ntlm/provider`)

* The default for "I have username + password and want it to work".
* Works against everything from Windows 2000 onwards and every modern
  Samba build.
* No clock-sync requirement, no KDC reachability requirement.
* Built-in support for `alConnect` (auth only), `alPktIntegrity` (sign),
  and `alPktPrivacy` (sign + seal). Most real-world servers require at
  least `alPktIntegrity` for sensitive opnums.
* Anonymous: `newNtlmAnonymousProvider("MSRPCNIM")` — for fingerprinting
  + the small set of opnums that don't require authn.

### SPNEGO (`msrpc/auth/spnego/provider`)

* Wraps an inner mech (NTLM or Kerberos) in the GSS-API negotiation
  envelope that SMB and HTTP both expect.
* For SMB specifically, you can usually skip SPNEGO and send a bare
  NTLM message — Windows accepts both. SPNEGO is mandatory for HTTP-
  based protocols (WinRM, MS-RPC over HTTP).
* Construction:
  - `newSpnegoProvider(ntlm)`     — NTLM as the inner mech
  - `newSpnegoKerberos(kerberos)` — Kerberos as the inner mech
* Per-message sign/seal pass through to the inner mech, so SPNEGO never
  costs you anything beyond a few bytes of token overhead.

### Kerberos (`msrpc/auth/kerberos/provider`)

* When you want what real domain-joined Windows clients use.
* Requires a reachable KDC, correct realm spelling (uppercase!), and
  clock skew within ~5 minutes of the KDC.
* Transport defaults to **TCP/88 with UDP/88 fallback** (`ktAuto`). TCP
  is what AD actually uses — AS-REPs contain a PAC and routinely exceed
  the path MTU. UDP-only is fine for MIT realms or anything without a
  PAC; force it with `transport = ktUdp`. The auto policy also retries
  on TCP if a UDP request comes back with `KRB_ERR_RESPONSE_TOO_BIG`
  (code 52).
* Two ETYPEs ship: **RC4-HMAC (23)** for compatibility with legacy
  accounts and **AES-256-CTS-HMAC-SHA1-96 (18)** for modern AD. Choose
  via `preferEtype`. AES-128 (17) also works but offers no advantage
  over AES-256 in practice.
* The provider auto-handles the `KDC_ERR_PREAUTH_REQUIRED` retry with
  PA-ENC-TIMESTAMP — you don't need to send two AS-REQs by hand.

```nim
import msrpc/auth/kerberos/[provider, rc4, etype]
let krb = newKerberosProvider(
  realm = "CORP.LOCAL",
  username = "alice",
  password = "P@ssw0rd!",
  kdcHost = "dc01.corp.local",
  preferEtype = EtypeAes256,        # or krbRc4.EtypeRc4Hmac
  transport = ktAuto)               # ktTcp / ktUdp / ktAuto (default)
let spnego = newSpnegoKerberos(krb)
# spnego can now be passed wherever an AuthProvider is expected
```

**Decision tree:**
* Talking to mainstream Windows/Samba and have a password? → **NTLM**.
* Talking to HTTP-based MS protocols (WinRM, RPC-over-HTTPS)? →
  **SPNEGO wrapping NTLM**.
* Domain integration test? Need to validate AD-side audit logging shows
  Kerberos auth? Forced AES-only environment? → **Kerberos** (wrap in
  SPNEGO for SMB).

---

## 4. Mid-level: do something the high-level API doesn't

### 4.1 Call an opnum that isn't already wrapped

Pattern: build the request stub by hand with NDR, call `rpc.call`,
parse the reply.

```nim
import msrpc/ndr/[context, primitives, strings]
import msrpc/rpc/client

# Manually marshal arguments for an opnum we don't have a stub for.
let c = newNdrEncode(nsNdr)        # nsNdr64 if NDR64 was negotiated
marshalU32(c, 0x12345678'u32)
marshalUnicodeString(c, "TargetName")
let stub = c.finish()

let reply = rpc.call(opnum = 42, stub = stub)

let d = newNdrDecode(reply, nsNdr)
var status: uint32
marshalU32(d, status)
echo "raw status = 0x", toHex(int(status), 8)
```

The mid-level rule: **always check what NDR flavour was negotiated** by
inspecting the syntax UUID on the bind. Use the same flavour for the
decode context as for the encode context. Mixing them silently produces
garbage.

### 4.2 Custom transport

Subclass `rpc.Transport` and implement `send` / `recv` / `close`. The
RPC client doesn't care whether bytes flow over TCP, a named pipe, a
unix socket, or `/dev/null`. The named-pipe transport in
`rpc/transport_np.nim` is a 60-line reference.

### 4.3 LDAP filters more complex than equality

`ldap/messages.nim` exports `buildAndFilter`, `buildOrFilter`,
`buildNotFilter`, `buildPresenceFilter`, `buildEqualityFilter`,
`buildSubstringFilter`. Compose them like the LDAP filter mini-language:

```nim
# (&(objectClass=user)(|(sAMAccountName=alice)(sAMAccountName=bob)))
let f = buildAndFilter(@[
  buildEqualityFilter("objectClass", cast[seq[byte]](@"user")),
  buildOrFilter(@[
    buildEqualityFilter("sAMAccountName", cast[seq[byte]](@"alice")),
    buildEqualityFilter("sAMAccountName", cast[seq[byte]](@"bob")),
  ]),
])
```

### 4.4 Sign / seal a single PDU

Useful when wrapping a non-RPC protocol that needs the same
GSS_Wrap-style integrity:

```nim
import msrpc/auth/ntlm/provider
let p = newNtlmProvider("CORP", "alice", "P@ssw0rd!", "MSRPCNIM",
                         authLevel = alPktPrivacy)
discard p.initialize("cifs/dc01.corp.local")
discard p.step(serverChallenge)        # complete the handshake

var pdu = @[byte('h'), byte('i')]
let verifier = p.rpcSignSeal(pdu, sealLen = 2)
# pdu is now sealed in place; `verifier` is the security trailer
# the receiver passes both back into rpcUnsealVerify.
```

---

## 5. Low-level: the primitives

### 5.1 Byte buffers (`common/buffers`)

A `Buffer` is a `seq[byte]` with a cursor. One Buffer is both reader
and writer; you can switch directions with `seek`. NDR alignment uses
this directly:

```nim
let b = newBuffer()
b.writeU32LE(0x12345678'u32)
b.writeU16LE(0xABCD'u16)
b.alignTo(4)                  # pad to 4-byte boundary for the next field
b.writeU64LE(0xCAFEBABEDEADBEEF'u64)
let bytes = b.consumed        # the seq[byte] written so far

let r = newBuffer(bytes)
let x = r.readU32LE()
let y = r.readU16LE()
r.alignTo(4)
let z = r.readU64LE()
```

`b.pos` is the cursor; `b.data` is the underlying seq. Past the
high-water mark, the buffer is implicitly zero-filled when you write.

### 5.2 NDR (`ndr/`)

The mental model: an `NdrContext` is a *direction-aware* buffer with
alignment-aware primitives. The same `marshal(c, v)` proc serves
encode and decode — it dispatches on `c.dir` and either writes `v` to
`c.buf` or reads it out. So your type's `marshal` proc looks the same
on both sides.

Pointers in NDR are a two-pass dance:
1. The pointer slot (top-level or embedded) gets a referent ID.
2. The pointee is queued for emission **at the end** of the surrounding
   structure (deferral).

The context carries that deferred queue. When you finish a struct, you
must drain its deferred queue or the bytes are wrong on the wire.
`primitives.nim` calls `c.drainDeferred()` at the right boundaries; if
you write your own struct marshal, you need to too — see
`proto/lsarpc/idl.nim` for the pattern.

NDR3 vs NDR64: counts are u32 in NDR3, u64 in NDR64. Conformant array
headers go from 4 bytes to 8 bytes. Some structs have explicit
`size_is` modifiers that change the wire form. The context's `syntax`
field flips the behavior — your code looks identical either way.

### 5.3 Crypto (`crypto/`)

Everything is pure Nim. Listed by spec:

| Module             | Spec                       | Use                        |
|--------------------|----------------------------|----------------------------|
| `md4.nim`          | RFC 1320                   | NTOWF, RC4-HMAC base key   |
| `md5.nim`          | RFC 1321                   | NTLM sign+seal             |
| `hmac.nim`         | RFC 2104 (with MD5)        | NTLMv2 derivations         |
| `rc4.nim`          | (no RFC — Schneier App. C) | NTLM sealing, RC4-HMAC     |
| `sha1.nim`         | FIPS 180-4                 | Kerberos AES HMAC          |
| `sha256.nim`       | FIPS 180-4                 | SMB 2.1 / SMB 3.1.1        |
| `hmac_sha.nim`     | RFC 2104 (with SHA)        | Kerberos AES, KDFs         |
| `aes.nim`          | FIPS 197                   | Kerberos AES, SMB3 crypto  |
| `aes_cmac.nim`     | RFC 4493                   | SMB 3.x signing            |
| `aes_ccm.nim`      | RFC 3610                   | SMB 3.x encryption         |
| `kdf.nim`          | RFC 2898, SP 800-108       | PBKDF2, SMB3 key schedule  |
| `rand.nim`         | (OS CSPRNG)                | nonces, confounders, salt  |

Use them directly when you need: an AES-CMAC tag, a SHA-256 hash, a
PBKDF2 derivation. No need to drag the protocol layers in.

### 5.4 DER / BER (`auth/spnego/asn1.nim`, `ldap/ber.nim`)

Hand-rolled, definite-length, tag-explicit. Two helpers handle 90% of
real-world cases:

* `derTLV(tag, value)`  — wrap `value` in a tag + length byte(s).
* `b.derReadTag(expected)` — read a tag, raise if it's not what we want,
  return the length.

The SPNEGO module exports the base constants (`tagSequence`, `tagOid`,
`ctxConstructed(n)`, `appConstructed(n)`). The LDAP module extends with
`berBoolean` / `berInteger` helpers for LDAP-specific types.

If you need OID encoding, `derEncodeOid(@[1, 3, 6, 1, ...])` does the
40*a + b first-pair thing and the base-128 continuation bit thing for
you.

### 5.5 Transports (`rpc/transport_tcp.nim`, `rpc/transport_np.nim`)

Both implement `Transport`. The TCP one connects, sends, receives. The
named-pipe one wraps an `SmbPipe` and uses `IOCTL FSCTL_PIPE_TRANSCEIVE`
for the round-trip RPC pattern. Adding a third (say, HTTPS for
RPC-over-HTTP) is a matter of implementing `send`/`recv`/`close`.

### 5.6 SMB primitives (`smb/client.nim`, `smb/header.nim`, `smb/smb3.nim`)

The high-level `newSmbSession` does the whole NEGOTIATE / SESSION_SETUP
/ TREE_CONNECT dance and returns a usable session. If you need to
debug, the constituents are public:

* `buildNegotiateBody(dialects)` — produces just the NEGOTIATE body
  (no header). Useful for inspecting what your client offers.
* `s.openPipe("samr")` — open a named pipe on the established session.
* `pipe.transceive(data)` — single round-trip RPC via
  `FSCTL_PIPE_TRANSCEIVE`.
* `maybeSignOrEncrypt(s, payload)` — apply the SMB 3.x sign-or-encrypt
  decision for one PDU. Returns the on-wire bytes.

---

## 6. Understanding what's happening on the wire

This section is the why-things-are-shaped-this-way explainer.

### 6.1 The NTLM handshake

Three messages — that's all NTLM is. NEGOTIATE, CHALLENGE,
AUTHENTICATE. Client sends NEGOTIATE with the flags it supports.
Server responds with CHALLENGE containing an 8-byte random nonce
("server challenge") and a list of target info AV pairs. Client
computes the response (HMAC-MD5 of NT-hash and the challenge +
client-side data), sends AUTHENTICATE. Done.

Two subtle things the spec leaves implicit:

* The AUTHENTICATE message's MIC is computed *before* it's inserted —
  so the MIC bytes inside the message are zero when you compute, and
  then you patch them in. Whether the MIC offset is 64 or 72 bytes
  into the message depends on whether `NEGOTIATE_VERSION` is in the
  *negotiated* flags, not the locally-built flags. We hit this — see
  bug #9 in the README.

* The `MsvAvTimestamp` AV pair in the CHALLENGE must be echoed
  verbatim in the AUTHENTICATE's NTLMv2 response. Using the local
  clock works against time-synced labs and fails in production. See
  bug #2.

### 6.2 Sign and seal

Once the handshake is done, every subsequent message has a *security
trailer*: 16 bytes containing an HMAC-MD5 of (sequence number + body)
truncated to 8 bytes. Sealing means: encrypt the body with RC4 keyed
on a derived key, then sign over the *plaintext* (not the ciphertext).
The receiver decrypts first, then verifies.

Sequence numbers start at 0 and increment on every PDU. **Client and
server keep separate counters per direction.** If you send three PDUs
and the server replies once, your send-counter is at 3 and your
receive-counter is at 1.

This is why one auth provider per binding matters. The provider holds
the counters. Two RPC clients sharing one provider would clobber
counters.

### 6.3 SMB2 vs SMB3 negotiate

SMB2 dialects 2.0.2 and 2.1 use a simple NEGOTIATE request: list of
dialects, server picks the highest it supports.

SMB 3.x adds *negotiate contexts* (3.1.1 only): blobs of structured
data appended after the dialect list that say "I can do these hashes
for preauth integrity" and "I can do these AES modes for transport
encryption". The trick is that the dialect list must be padded to an
8-byte boundary, and the context offset in the header must point to
where the contexts actually start. Get the alignment wrong and a
3.1.1 server returns `STATUS_INVALID_PARAMETER` with no other
explanation.

This library offers 2.0.2 / 2.1 / 3.0 / 3.0.2 by default and 3.1.1
opt-in. The reason 3.1.1 is opt-in: the *preauth hash* (a running
SHA-512 over every NEGOTIATE and SESSION_SETUP message) needs to be
threaded through the session-setup state machine, and that's a fair
chunk of state work that isn't worth doing if you only need to talk to
boring file servers.

### 6.4 SMB3 sign vs SMB3 encrypt

After the session is set up, derived keys come out of a SP 800-108
KDF rooted at the NTLM exported session key (or Kerberos session key).
Four keys:

* **Signing key**: AES-CMAC over the whole SMB2 PDU with signature
  bytes 48..63 zeroed. Result goes in those 16 bytes.
* **Encrypt key**: AES-CCM over the SMB2 PDU body with a fresh nonce.
  Output: TRANSFORM_HEADER (prepended) + ciphertext.
* **Decrypt key**: same algorithm, mirror direction.
* **Application key**: used downstream by some protocols
  (RPC over named pipe doesn't use it).

Whether a PDU is signed or encrypted depends on:
* Signing is required when the server's NEGOTIATE response says so.
* Encryption is required when the SESSION_SETUP response sets
  `SMB2_SESSION_FLAG_ENCRYPT_DATA` (bit 2 of SessionFlags).
* Encryption *replaces* signing — under the transform header the
  signature field is irrelevant.

The library auto-detects both. You don't have to choose.

### 6.5 Kerberos: the three-step ticket dance

If NTLM is "prove you know the password by HMAC'ing the challenge",
Kerberos is "prove it once to the KDC, then carry KDC-signed tickets
to everyone else".

1. **AS-REQ → AS-REP**: client asks the KDC for a Ticket-Granting
   Ticket (TGT). Modern AD always demands pre-authentication: the
   client must include a `PA-ENC-TIMESTAMP` (current time encrypted
   under the user's long-term key) to prove possession of the
   password. Without it the KDC returns `KDC_ERR_PREAUTH_REQUIRED`
   (code 25). The library handles the retry automatically.

   The AS-REP contains the encrypted "EncASRepPart" which the client
   decrypts with the user's key. Inside is the **TGT session key** —
   a fresh key the KDC chose, shared between client and KDC. The TGT
   itself is *opaque* to the client: it's encrypted under the krbtgt
   service key and only the KDC can read it.

2. **TGS-REQ → TGS-REP**: client wants to talk to a service (say,
   `cifs/dc01.corp.local`). Client sends a TGS-REQ with a PA-TGS-REQ
   containing an **AP-REQ to krbtgt** (i.e., an authenticator
   encrypted under the TGT session key). The KDC verifies, sees who
   the client is, and issues a service ticket plus a fresh **service
   session key**.

3. **AP-REQ to the service**: client sends an AP-REQ containing the
   service ticket (which the service can decrypt with its long-term
   key) plus an Authenticator (encrypted under the service session
   key). The service decrypts the ticket, gets the session key out,
   decrypts the Authenticator, learns who the client is.

After step 3, both sides share the service session key. SPNEGO wraps
the AP-REQ as the initial token; per-message sign+seal uses derived
sub-keys (`Ke = DK(K, usage || 0xAA)`, `Ki = DK(K, usage || 0x55)`)
the same way Kerberos derives any per-usage key (see §6.6).

Things people get wrong:
* **Realm casing**: Kerberos realms are case-sensitive in the wire
  encoding. `CORP.LOCAL` and `corp.local` are different realms. Always
  use uppercase.
* **Clock skew**: the Authenticator includes the current time. The
  service rejects with `KRB_AP_ERR_SKEW` if your clock is more than
  ~5 minutes off. Sync your client.
* **SPN format**: service tickets are for a specific SPN. Asking for
  `cifs/dc01.corp.local` is different from `cifs/dc01`. Use the
  fully-qualified form everywhere.

### 6.6 Why Kerberos has so many derived keys

A single Kerberos session can encrypt or sign many different things:
the AS-REQ pre-auth timestamp, the AS-REP enc-part, the TGS-REP
enc-part, the AP-REQ authenticator, the per-message GSS_Wrap payloads,
etc. If they all used the same key, a vulnerability in any one usage
would compromise them all.

So Kerberos derives a *per-usage subkey* using the **DK function**
(RFC 3961 §5.3):

```
DK(K, constant) = random-to-key(DR(K, constant))
DR(K, constant) = repeated AES(K, n-fold(constant)) | AES(K, prev) | ...
                  truncated to key-length bytes
```

The `constant` is `BE32(usage) || selector_byte`, where:
* `0xAA` = encryption key (Ke)
* `0x55` = integrity key (Ki)
* `0x99` = checksum key (Kc)

So usage 1 (AS-REQ PA-ENC-TIMESTAMP) has its own Ke and Ki, usage 3
(AS-REP enc-part) has different Ke and Ki, etc. Same base key,
totally different per-usage keys. Cross-usage attacks become hard.

### 6.7 NDR alignment, the bottomless pit

The NDR rule is: every value aligns to its size, up to 8 bytes. A u32
aligns to 4. A u64 aligns to 8. A struct aligns to the alignment of
its most-aligned member. Strings align to 4 (because they start with
a u32 max-count). Arrays align to the alignment of their element.

Alignment is *relative to the start of the structure*, not the start
of the buffer. Then everything inside a top-level structure aligns
relative to the top-level start. There are subtle interactions when
you have a pointer to a struct that contains a pointer to a struct;
the deferred pointee is emitted aligned to its own type's alignment,
counted from the *deferred bytes' start*, not from where the pointer
slot was.

When something goes wrong with NDR decoding, 90% of the time it's an
off-by-some alignment issue. Bug #8 in the README is a worked example:
`LSAPR_TRANSLATED_NAME` has a `SID_NAME_USE` (u16) followed by an
`RPC_UNICODE_STRING` (which is a struct containing a u32). The u16
needs a 2-byte alignment slot before it; then *after* the u16 you need
to align to 4 before reading the RPC_UNICODE_STRING. Forget that pad
and you read junk.

---

## 7. Common patterns and pitfalls

### 7.1 "STATUS_ACCESS_DENIED" after my second RPC call

Probably reusing one auth provider across two RPC clients. Make a
fresh provider per client. Sequence counters are per-provider, not
per-client.

### 7.2 "STATUS_PIPE_BUSY" mid-conversation

Probably sending AUTH3 via `transceive` (which expects a response)
instead of `write` (one-way). AUTH3 doesn't get a response on the
named pipe; the server just notes it. Use the one-way primitive.

### 7.3 "EPT_S_NOT_REGISTERED" against Samba

EPM lookup against minimal Samba builds often fails because Samba
doesn't always register endpoints with the EPM. Use SMB named pipes
instead (e.g., `\samr`, `\lsarpc`).

### 7.4 NTLMv2 works in dev, fails in prod with clock skew

You're using the local clock in the NTLM response. Echo the server's
`MsvAvTimestamp` AV pair verbatim instead. The library does this
automatically; if you're hand-rolling, make sure your code does too.

### 7.5 Kerberos AS-REQ gets `KDC_ERR_C_PRINCIPAL_UNKNOWN`

Username casing or realm casing. Try `Administrator@CORP.LOCAL`
spelled exactly as the KDC has it. The library accepts the username
as you pass it; AD is strict about case.

### 7.6 SMB3 connection drops right after NEGOTIATE

Server hates your dialect list ordering, or your negotiate contexts
are misaligned. Drop to a smaller dialect set
(`[Smb202, Smb210, Smb300, Smb302]`) and see if that works; if it
does, your 3.1.1 context offset is wrong.

### 7.7 "I get random bytes back from the server"

NDR3 vs NDR64 mismatch. Check the syntax UUID on the bind-ack — if
the server picked NDR64, your encode/decode contexts must both be
`nsNdr64`.

### 7.8 Anonymous NTLM gets `STATUS_INVALID_PARAMETER`

Strip `NEGOTIATE_VERSION` and `NEGOTIATE_ANONYMOUS` from the
AUTHENTICATE flags. Bug #7. Use `newNtlmAnonymousProvider`, which
does it for you.

---

## 8. Debugging

### 8.1 Print what you're about to send

Every layer's buffer has a `.hex()` method (or you can `toHex` the
bytes). Drop a `echo b.consumed.toHex` before `s.send` and compare
against a Wireshark capture from impacket or a working Windows client.

### 8.2 Compare with impacket byte-for-byte

This is the highest-leverage debugging tool for "what byte am I off
by". Capture a working impacket exchange with `pyshark` or by piping
`socat` between client and server with logging. Then run your code and
diff.

### 8.3 The fuzzer caught real bugs

```
MSRPC_FUZZ_BUDGET_MS=30000 nim r --path:src tests/fuzz/fuzz_runner.nim
```

Random + structured inputs against every decoder. When something
crashes, the seed is printed so you can reproduce. The bug-fix table
in the README has two entries that were found this way (the
`parseBindAckBody` RangeDefect and the four bugs from the first run).
If you add a new decoder, add a fuzz target for it.

### 8.4 The live test harness is env-gated

`tests/live/tlive_smoke.nim` runs against a real server when env vars
are set. Useful as a quick "does anything still work" check after a
big refactor. The tests print bytes on failure; copy them into your
debugger.

---

## 9. Where to look in the code

When you're trying to find out how X works, here's where to start:

| Question | File |
|---|---|
| How is an NTLM message framed? | `src/msrpc/auth/ntlm/messages.nim` |
| How does sign+seal work end-to-end? | `src/msrpc/auth/ntlm/session.nim` |
| How does Kerberos build an AS-REQ? | `src/msrpc/auth/kerberos/messages.nim` |
| What's in an AP-REQ? | `src/msrpc/auth/kerberos/apreq.nim` |
| Where does NDR alignment happen? | `src/msrpc/ndr/primitives.nim` + `arrays.nim` |
| How does the bind state machine work? | `src/msrpc/rpc/client.nim` |
| How does SMB negotiate? | `src/msrpc/smb/client.nim::buildNegotiateBody` |
| How are SMB3 keys derived? | `src/msrpc/smb/smb3.nim::derive30Keys` / `derive311Keys` |
| What's an example of a clean opnum stub? | `src/msrpc/proto/lsarpc/idl.nim` |

When you're looking for "an example test that does X end-to-end":

| Test | Covers |
|---|---|
| `tests/integration/tloopback.nim` | Client+server in one process, full RPC over TCP |
| `tests/integration/tauth_loopback.nim` | BIND with auth + AUTH3 + sealed REQUEST |
| `tests/unit/auth/kerberos/taes_profile.nim` | AES-CTS-HMAC-SHA1-96 round-trip + tamper detection |
| `tests/unit/smb/tsign_encrypt.nim` | SMB3 signing patches the right bytes; encrypt round-trips |
| `tests/live/tlive_smoke.nim` | Real-DC smoke (env-gated) |

---

## 10. When this library isn't the right tool

* **You need full Active Directory replication (MS-DRSR).** Not
  supported. impacket's `secretsdump` is the reference.
* **You need DCOM / WMI.** No DCOM at all yet — those are
  multi-protocol bindings over OXID resolver, not just one RPC.
* **You need MS-RPC over HTTPS for Exchange/WinRM.** SPNEGO is there;
  the HTTP transport isn't.
* **You're hot-path encrypting many GBs.** AES is pure Nim, not
  hardware-accelerated. Throughput is fine for one-off auth (KB/s) but
  not bulk transfer (GB/s). For bulk SMB you'd want to wire AES-NI via
  `{.compile.}` directives, or use libsodium for the AES bits.

Otherwise: yes, this library is the right tool, especially if you
care about (a) cross-platform (Linux/Mac/Windows from one codebase),
(b) zero binary dependencies, (c) being able to read and modify every
byte of the wire format.
