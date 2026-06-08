## examples/ldapquery.nim — query a directory server via LDAP.
##
## Usage:
##   LDAP_HOST=dc01.corp ldapquery
##     anonymous bind + search rootDSE for namingContexts
##
##   LDAP_HOST=dc01.corp LDAP_USER='CN=alice,...' LDAP_PASS=... ldapquery
##     authenticated bind + same search
##
## On Active Directory, anonymous binds are usually rejected; on
## OpenLDAP and most other directory servers the rootDSE is readable
## anonymously.

import std/[os, strutils]
import msrpc/ldap/[messages, client]

let host = getEnv("LDAP_HOST")
let portEnv = getEnv("LDAP_PORT")
let port = if portEnv.len > 0: parseInt(portEnv) else: 389
let bindDn = getEnv("LDAP_USER")
let pass = getEnv("LDAP_PASS")
doAssert host.len > 0, "set LDAP_HOST"

let c = newLdapClient(host, port)
let b = c.bindSimple(bindDn, pass)
echo "Bind: ", resultName(b.resultCode),
     (if b.diagnosticMessage.len > 0: " — " & b.diagnosticMessage else: "")
if b.resultCode != 0: c.close(); quit(1)

let filter = buildPresenceFilter("objectClass")
let r = c.search(baseDn = "", scope = lsBaseObject, filter = filter,
                 attributes = @["namingContexts", "supportedSASLMechanisms",
                                 "supportedLDAPVersion", "vendorName",
                                 "currentTime", "defaultNamingContext"])
echo "rootDSE entries: ", r.entries.len
for entry in r.entries:
  echo "DN: ", entry.dn
  for attr in entry.attributes:
    for v in attr.values:
      echo "  ", attr.name, " = ", valueAsString(v)
echo "Done: ", resultName(r.done.resultCode)

c.unbind()
