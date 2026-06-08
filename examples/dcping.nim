## examples/dcping.nim — CLDAP netlogon ping for AD discovery.
##
## Usage:
##   dcping <host>                   ask for any DC for this host's domain
##   dcping <host> <domain.fqdn>     specifically ask for `domain.fqdn`
##
## Returns: forest, domain, DC hostname, site, flags. Same info
## `nltest /dsgetdc:` returns.

import std/[os, strutils]
import msrpc/ldap/cldap

let host = if paramCount() >= 1: paramStr(1) else: ""
let dom  = if paramCount() >= 2: paramStr(2) else: ""

if host.len == 0:
  echo "usage: dcping <host> [domain.fqdn]"
  quit(1)

try:
  let r = cldapNetlogonPing(host, dnsDomain = dom)
  echo "Opcode           : 0x", toHex(int(r.opcode), 4)
  echo "Flags            : ", r.flags
  echo "Domain GUID      : "
  for i, b in r.domainGuid:
    stdout.write(toHex(int(b), 2))
    if i in {3, 5, 7, 9}: stdout.write('-')
  echo ""
  echo "DNS Forest       : ", r.dnsForest
  echo "DNS Domain       : ", r.dnsDomain
  echo "DNS Hostname     : ", r.dnsHostname
  echo "NetBIOS Domain   : ", r.netbiosDomain
  echo "NetBIOS Hostname : ", r.netbiosHostname
  echo "DC Site          : ", r.dcSiteName
  echo "Client Site      : ", r.clientSiteName
  echo "Version          : 0x", toHex(int(r.version), 8)
except CatchableError as e:
  echo "CLDAP ping failed: ", e.msg
  quit(2)
