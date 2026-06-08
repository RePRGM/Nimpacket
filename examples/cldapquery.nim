## examples/cldapquery.nim — issue arbitrary LDAP queries over UDP.
##
## Two modes:
##
##   cldapquery <host>
##     CLDAP root-DSE query for a few well-known operational attributes
##     (namingContexts, dnsHostName, supportedSASLMechanisms, currentTime,
##     ldapServiceName). This is what every AD client does immediately
##     after locating a DC.
##
##   cldapquery <host> "<filter>" "<attr,attr,attr>"
##     Custom search. The filter syntax is restricted to a single
##     equality predicate "attr=value" or a presence "attr=*" for
##     simplicity; combine multiple via the dcping flow if you need a
##     conjunction.
##
## CLDAP servers may refuse arbitrary base-DN queries — most only
## answer rootDSE searches anonymously, which is the whole point of
## the protocol.

import std/[os, strutils]
import msrpc/ldap/[messages, cldap]

proc parseSimpleFilter(s: string): seq[byte] =
  ## "attr=*"     → presence filter
  ## "attr=value" → equality filter
  let parts = s.split('=', 1)
  if parts.len != 2:
    raise newException(ValueError, "filter must be 'attr=value' or 'attr=*'")
  if parts[1] == "*":
    return buildPresenceFilter(parts[0])
  return buildEqualityFilter(parts[0], cast[seq[byte]](parts[1]))

let host = if paramCount() >= 1: paramStr(1) else: ""
if host.len == 0:
  echo "usage: cldapquery <host> [filter] [attr,attr,...]"
  quit(1)

let filterArg = if paramCount() >= 2: paramStr(2) else: "objectClass=*"
let attrsArg = if paramCount() >= 3: paramStr(3) else:
                  "namingContexts,dnsHostName,supportedSASLMechanisms," &
                  "currentTime,ldapServiceName,defaultNamingContext"

let attrs = attrsArg.split(',')
let filter = parseSimpleFilter(filterArg)

proc main() =
  let c = newCldapClient(host, port = 389, timeoutMs = 3000)
  defer: c.close()
  try:
    let r = c.cldapSearch(baseDn = "", scope = lsBaseObject,
                           filter = filter, attributes = attrs)
    echo "Entries returned: ", r.entries.len
    for entry in r.entries:
      echo "DN: ", (if entry.dn.len == 0: "<rootDSE>" else: entry.dn)
      for a in entry.attributes:
        for v in a.values:
          echo "  ", a.name, " = ", valueAsString(v)
    echo "Done: ", resultName(r.done.resultCode)
    if r.done.diagnosticMessage.len > 0:
      echo "Diagnostic: ", r.done.diagnosticMessage
  except CldapError as e:
    echo "CLDAP error: ", e.msg
    quit(2)

main()
