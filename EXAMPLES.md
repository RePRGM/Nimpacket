# Examples cookbook

Worked walkthroughs of every tool in `examples/`. Sample outputs are
representative of a real run; values have been generalized so they
don't reflect any specific machine's configuration.

---

## 1. Local SAM domain SID — `lsadom`

```
$ MSRPC_TEST_HOST=10.0.0.5 \
  MSRPC_TEST_USER=alice    \
  MSRPC_TEST_PASS='<password>' \
  MSRPC_TEST_DOMAIN=CORP   \
  nim r --path:src examples/lsadom.nim

Policy opened.
Account domain name : EXAMPLE-PC
Account domain SID  : S-1-5-21-1111111111-2222222222-3333333333
```

Pipeline: SMB2 NEGOTIATE / SESSION_SETUP / TREE_CONNECT IPC$ / CREATE
`\lsarpc` / RPC BIND (LSARPC) / `LsarOpenPolicy2` /
`LsarQueryInformationPolicy(PolicyAccountDomainInformation)` /
`LsarClose`. Equivalent to PsTools `psgetsid`.

---

## 2. Enumerate local users — `lsausers`

```
$ nim r --path:src examples/lsausers.nim

Local domain: EXAMPLE-PC
Local SID:    S-1-5-21-1111111111-2222222222-3333333333

Lookup status: 0x00000107   # STATUS_SOME_NOT_MAPPED
Referenced domains:
  [0] EXAMPLE-PC
RID translations:
  RID   500 : EXAMPLE-PC\Administrator (User)
  RID   501 : EXAMPLE-PC\Guest         (User)
  RID  1001 : EXAMPLE-PC\alice         (User)
  RID  1006 : EXAMPLE-PC\bob           (User)
```

Takes the local domain SID, appends common RIDs (500, 501, 1000+),
and uses `LsarLookupSids` to translate them in one batched call.
The 0x00000107 status is the standard "some RIDs didn't exist"
warning.

---

## 3. Enumerate SAM domains and users — `samrenum`

```
$ nim r --path:src examples/samrenum.nim

[1] SamrConnect5(MAXIMUM_ALLOWED) ...
    OK  handle uuid prefix=01000000
[2] SamrEnumerateDomainsInSamServer ...
    found 2 domain(s):
      Builtin
      EXAMPLE-PC
[3] SamrLookupDomainInSamServer(EXAMPLE-PC) ...
    SID: S-1-5-21-1111111111-2222222222-3333333333
[4] SamrOpenDomain ...
    OK
[5] SamrEnumerateUsersInDomain ...
    11 user(s):
      RID   500  Administrator
      RID   501  Guest
      ...
```

Needs an admin user. With a non-admin you'll get a clean RPC fault
at step 1, with `0x5` (ACCESS_DENIED), and the tool prints a hint
explaining why and exits cleanly. Note: Windows "Remote UAC token
filtering" may also deny this for local Administrators group members
authenticating remotely with a local account — use the built-in
Administrator or a domain admin, or set
`LocalAccountTokenFilterPolicy = 1` in registry (lowers default
hardening).

---

## 4. Service control — `sctl`

```
$ ./sctl status RpcSs

RpcSs:
  state           : RUNNING (4)
  service type    : 0x00000020
  win32 exit code : 0
  service exit    : 0
  check point     : 0
  wait hint       : 0
```

```
$ ./sctl enum         # needs SC_MANAGER_ENUMERATE_SERVICE (admin)

[truncated, 134560 bytes needed for full list]
Returned 412 service(s):
   RUNNING            RpcSs                          Remote Procedure Call (RPC)
   RUNNING            LanmanServer                   Server
   ...
```

`status` works for any authenticated user (CONNECT-only access).
`enum` requires admin rights (subject to Remote UAC filtering — see
note in §3).

---

## 5. Network shares — `netshares`

```
$ ./netshares

Shares on 10.0.0.5 (6 of 6):
                      NAME           TYPE  COMMENT
  ------------------------ --------------  ------------------------------
                    ADMIN$   DISK,SPECIAL  Remote Admin
                        C$   DISK,SPECIAL  Default share
                 Documents           DISK
                      IPC$    IPC,SPECIAL  Remote IPC
                     Media           DISK
                     Users           DISK
```

What `net view \\host` and `smbclient -L //host` print.

---

## 6. LDAP query — `ldapquery`

```
$ LDAP_HOST=ldap.example.com nim r --path:src examples/ldapquery.nim

Bind: rcSuccess
rootDSE entries: 1
DN:
  namingContexts = dc=example,dc=com
  supportedSASLMechanisms = GSSAPI
  supportedSASLMechanisms = PLAIN
  supportedLDAPVersion = 3
  vendorName = OpenLDAP Foundation
  currentTime = 20260608045023Z
Done: rcSuccess
```

Anonymous bind + rootDSE Search. For an authenticated bind, set
`LDAP_USER` and `LDAP_PASS`. AD usually rejects anonymous binds;
OpenLDAP and most other servers don't. Note: Windows *desktop*
editions don't run an LDAP service — point this at a real DC, a
Windows Server with AD DS, or any directory server.

---

## 7. Arbitrary CLDAP queries — `cldapquery`

```
$ ./cldapquery dc01.corp.example "objectClass=*" \
    "namingContexts,dnsHostName,currentTime"

Entries returned: 1
DN: <rootDSE>
  namingContexts = DC=corp,DC=example
  dnsHostName = dc01.corp.example
  currentTime = 20260608045023.0Z
Done: rcSuccess
```

Issues any LDAP Search over UDP/389 anonymously. Use a single
"attr=value" filter or "attr=*" for presence. Returns operational
attributes from the rootDSE, which is what every AD client does
during initial bootstrap.

---

## 8. AD DC discovery — `dcping`

```
$ ./dcping dc01.corp.example corp.example

Opcode           : 0x0017
Flags            : {PDC,GC,LDAP,DS,KDC,Timeserv,Closest,Writable,GoodTimeserv,DNS,DnsDomain,DnsForest}
Domain GUID      : 11223344-5566-7788-99aa-bbccddeeff00
DNS Forest       : corp.example
DNS Domain       : corp.example
DNS Hostname     : dc01.corp.example
NetBIOS Domain   : CORP
NetBIOS Hostname : DC01
DC Site          : Default-First-Site-Name
Client Site      : Default-First-Site-Name
Version          : 0x00000005
```

Wraps `cldapNetlogonPing` and decodes the binary
`NETLOGON_SAM_LOGON_RESPONSE_EX` blob. This is exactly what
`nltest /dsgetdc:` and `Get-ADDomainController -Discover` use to
locate a usable DC.

---

## 9. Interactive shell — `msrpc-repl`

```
$ ./msrpc-repl
msrpc-repl — type 'help' for commands, 'quit' to exit.
msrpc> connect 10.0.0.5 alice '<password>' CORP
  SMB session id=0x...
msrpc> use lsarpc
  bound to lsarpc
msrpc> lsa-open
  policy opened (access=0x00000801)
msrpc> lsa-domain
  domain name: EXAMPLE-PC
  domain SID : S-1-5-21-1111111111-2222222222-3333333333
msrpc> lookup-sids S-1-5-21-1111111111-2222222222-3333333333-500
  status: 0x00000000
  S-1-5-21-...-500 : EXAMPLE-PC\Administrator (type=1)
msrpc> quit
```

Commands: `connect`, `use lsarpc|samr`, `lsa-open`, `lsa-domain`,
`lookup-sids`, `samr-connect`, `samr-enum-domains`, `status`,
`close`, `help`, `quit`.

---

## 10. Generate a new protocol binding from MIDL — `idlgen`

Save a `.idl` snippet from Microsoft Open Specifications:

```idl
[uuid(76f226c3-ec14-4325-8a99-6a46348418af), version(1.0)]
interface MS_SCMR {
  typedef [context_handle] PVOID SC_RPC_HANDLE;
  DWORD ROpenSCManagerW(
    [in, unique, string] WCHAR *lpMachineName,
    [in, unique, string] WCHAR *lpDatabaseName,
    [in] DWORD dwDesiredAccess,
    [out] SC_RPC_HANDLE *lpScHandle);
  DWORD RCloseServiceHandle(
    [in, out] SC_RPC_HANDLE *hSCObject);
}
```

```
$ ./idlgen scmr.idl -o src/msrpc/proto/scmr/idl.nim
```

The generated file is a starting point — for protocols with complex
NDR patterns (unique-string buffers, switched unions, sized
conformant arrays with deferred bodies) you'll edit by hand. Use
`proto/lsarpc/idl.nim` as a reference for the patterns the generator
doesn't cover.

---

## 11. SPNEGO-wrapped NTLM

```nim
import msrpc/auth/ntlm/provider
import msrpc/auth/spnego/provider as spnego

let inner = newNtlmProvider("CORP", "alice", "<password>", "myhost")
let auth  = newSpnegoProvider(inner)
# pass `auth` to `connect()` instead of the bare NTLM provider.
```

Modern Windows often prefers SPNEGO-wrapped tokens, and the wrapper
adds future-proofing for Kerberos.

---

## 12. Tier C live tests against your own infrastructure

```
$ MSRPC_TEST_HOST=10.0.0.5 \
  MSRPC_TEST_USER=alice    \
  MSRPC_TEST_PASS='<password>' \
  MSRPC_TEST_DOMAIN=CORP   \
  nimble test_live
```

Tests skip cleanly when env vars are absent, so `nimble test`
(without `_live`) is safe in CI.
