## msrpc/repl.nim — interactive shell for talking to RPC services.
##
## Built as a thin command-dispatch loop over the library; each command
## corresponds to a primitive operation we already implement. Designed
## to be the Nim equivalent of Samba's `rpcclient` for the protocols
## this library covers (currently LSARPC and SAMR).
##
## Build:   nim c -o:msrpc-repl src/msrpc/repl.nim
## Use:     ./msrpc-repl

import std/[strutils, terminal]
import common/[guid, sid, status]
import auth/ntlm/provider
import smb/client as smb
import rpc/[client, transport_np]
import proto/lsarpc/idl as lsarpc
import proto/samr/idl as samr

type
  SessionKind = enum skNone, skLsarpc, skSamr

  Session = ref object
    host*: string
    user*, pass*, domain*: string
    smbSession*: SmbSession
    rpcClient*: RpcClient
    kind*: SessionKind
    lsaPolicy*: lsarpc.LsarHandle
    lsaPolicyOpen*: bool
    samrServer*: samr.SamrHandle
    samrServerOpen*: bool

# --- output helpers --------------------------------------------------

proc say(s: string) =
  styledWrite(stdout, fgGreen, "  ", resetStyle, s, "\n")
proc err(s: string) =
  styledWrite(stdout, fgRed, "  error: ", resetStyle, s, "\n")
proc info(s: string) =
  styledWrite(stdout, fgCyan, "  ", resetStyle, s, "\n")

# --- command implementations ----------------------------------------

proc cmdConnect(s: Session; args: seq[string]) =
  if args.len < 4:
    err("usage: connect <host> <user> <pass> <domain>")
    return
  if s.smbSession != nil:
    info("already connected; use 'close' first to switch hosts")
    return
  s.host = args[0]; s.user = args[1]; s.pass = args[2]; s.domain = args[3]
  let smbProv = newNtlmProvider(s.domain, s.user, s.pass, "MSRPCNIM")
  try:
    s.smbSession = newSmbSession(s.host, 445, smbProv, "cifs/" & s.host)
    say("SMB session id=0x" & toHex(int64(s.smbSession.sessionId), 16) &
        "  tree=0x" & toHex(int64(s.smbSession.treeId), 8))
  except CatchableError as e:
    err(e.msg)

proc cmdUse(s: Session; args: seq[string]) =
  if args.len < 1:
    err("usage: use <lsarpc|samr>")
    return
  if s.smbSession == nil:
    err("not connected; run 'connect' first"); return
  if s.rpcClient != nil:
    try: s.rpcClient.close() except CatchableError: discard
    s.rpcClient = nil
  s.kind = skNone
  let pipe = case args[0]
             of "lsarpc": "lsarpc"
             of "samr":   "samr"
             else:
               err("unknown service: " & args[0]); return
  let smbPipe = s.smbSession.openPipe(pipe)
  let transport = newNamedPipeTransport(smbPipe)
  let useUuid = if pipe == "lsarpc": lsarpc.LsarInterfaceUuid
                else: samr.SamrInterfaceUuid
  let useMajor = if pipe == "lsarpc": lsarpc.LsarInterfaceMajor
                 else: samr.SamrInterfaceMajor
  s.rpcClient = connect(transport, parseUuid(useUuid),
                         interfaceVersion = uint32(useMajor))
  s.kind = if pipe == "lsarpc": skLsarpc else: skSamr
  say("bound to " & args[0])

proc cmdLsaOpen(s: Session; args: seq[string]) =
  if s.kind != skLsarpc:
    err("not bound to lsarpc; run 'use lsarpc'"); return
  let mask = if args.len >= 1: parseHexInt(args[0]).uint32
             else: lsarpc.POLICY_VIEW_LOCAL_INFORMATION or lsarpc.POLICY_LOOKUP_NAMES
  let st = s.rpcClient.lsarOpenPolicy2("", mask, s.lsaPolicy)
  if st.isSuccess:
    s.lsaPolicyOpen = true
    say("policy opened (access=0x" & toHex(int(mask), 8) & ")")
  else:
    err("LsarOpenPolicy2: " & $st)

proc cmdLsaDomainInfo(s: Session) =
  if not s.lsaPolicyOpen:
    err("policy not open; run 'lsa-open'"); return
  var info: lsarpc.PolicyAccountDomainInfo
  let st = s.rpcClient.lsarQueryAccountDomain(s.lsaPolicy, info)
  if st.isSuccess:
    say("domain name: " & info.domainName)
    if info.hasSid:
      say("domain SID : " & $info.domainSid)
  else:
    err("Query failed: " & $st)

proc cmdLsaLookupSids(s: Session; args: seq[string]) =
  if not s.lsaPolicyOpen:
    err("policy not open; run 'lsa-open'"); return
  if args.len == 0:
    err("usage: lookup-sids <SID> [<SID>...]"); return
  var sids: seq[Sid]
  for sidText in args:
    try: sids.add parseSid(sidText)
    except CatchableError as e:
      err("bad SID '" & sidText & "': " & e.msg); return
  var res: lsarpc.LookupSidsResult
  let st = s.rpcClient.lsarLookupSids(s.lsaPolicy, sids, res)
  say("status: 0x" & toHex(int64(uint32(st)), 8))
  for i, sidText in args:
    if i >= res.names.len:
      info(sidText & " : <no result>")
    else:
      let n = res.names[i]
      let dom = if n.domainIndex >= 0 and n.domainIndex < res.domains.len:
                  res.domains[n.domainIndex] else: "?"
      if n.name.len > 0:
        info(sidText & " : " & dom & "\\" & n.name & " (type=" & $n.sidUse & ")")
      else:
        info(sidText & " : <unmapped>")

proc cmdSamrConnect(s: Session; args: seq[string]) =
  if s.kind != skSamr:
    err("not bound to samr; run 'use samr'"); return
  let mask = if args.len >= 1: parseHexInt(args[0]).uint32
             else: samr.SAMR_MAXIMUM_ALLOWED
  try:
    let st = s.rpcClient.samrConnect5("", mask, s.samrServer)
    if st.isSuccess:
      s.samrServerOpen = true
      say("server handle opened")
    else:
      err("SamrConnect5: " & $st)
  except CatchableError as e:
    err(e.msg)

proc cmdSamrEnumDomains(s: Session) =
  if not s.samrServerOpen:
    err("not connected; run 'samr-connect'"); return
  var ctx: uint32 = 0
  var res: samr.EnumerateResult
  try:
    let st = s.rpcClient.samrEnumerateDomainsInSamServer(
                s.samrServer, ctx, 0x10000'u32, res)
    say("status: " & $st & "  count: " & $res.countReturned)
    for e in res.entries: info("  rid=" & $e.rid & "  " & e.name)
  except CatchableError as e: err(e.msg)

proc cmdClose(s: Session) =
  if s.lsaPolicyOpen:
    var h = s.lsaPolicy
    discard s.rpcClient.lsarClose(h)
    s.lsaPolicyOpen = false
  if s.samrServerOpen:
    var h = s.samrServer
    discard s.rpcClient.samrCloseHandle(h)
    s.samrServerOpen = false
  if s.rpcClient != nil:
    try: s.rpcClient.close() except CatchableError: discard
    s.rpcClient = nil
  s.kind = skNone
  say("closed RPC binding")

proc cmdHelp() =
  echo """
Commands:
  connect <host> <user> <pass> <domain>   open SMB session
  use     <lsarpc|samr>                    bind to RPC interface
  lsa-open [access-mask-hex]               LsarOpenPolicy2
  lsa-domain                               local account domain (SID+name)
  lookup-sids <SID> [<SID>...]             translate SIDs to names
  samr-connect [access-mask-hex]           SamrConnect5
  samr-enum-domains                        list SAM domain names
  status                                   show current session state
  close                                    close RPC binding (keep SMB)
  quit/exit                                quit
  help                                     this list
"""

proc cmdStatus(s: Session) =
  if s.smbSession == nil:
    info("not connected")
  else:
    info("host=" & s.host & "  user=" & s.user & "  domain=" & s.domain)
    info("SMB session=0x" & toHex(int64(s.smbSession.sessionId), 16))
    info("RPC bound to: " & (case s.kind
                              of skNone: "(none)"
                              of skLsarpc: "lsarpc"
                              of skSamr: "samr"))

proc dispatch(s: Session; line: string): bool =
  let parts = line.strip().splitWhitespace()
  if parts.len == 0: return true
  case parts[0]
  of "quit", "exit":          return false
  of "help":                  cmdHelp()
  of "connect":               cmdConnect(s, parts[1..^1])
  of "use":                   cmdUse(s, parts[1..^1])
  of "lsa-open":              cmdLsaOpen(s, parts[1..^1])
  of "lsa-domain":            cmdLsaDomainInfo(s)
  of "lookup-sids":           cmdLsaLookupSids(s, parts[1..^1])
  of "samr-connect":          cmdSamrConnect(s, parts[1..^1])
  of "samr-enum-domains":     cmdSamrEnumDomains(s)
  of "status":                cmdStatus(s)
  of "close":                 cmdClose(s)
  else:                       err("unknown command — try 'help'")
  return true

when isMainModule:
  echo "msrpc-repl — type 'help' for commands, 'quit' to exit."
  let session = Session()
  while true:
    stdout.styledWrite(fgYellow, "msrpc> ", resetStyle)
    let line =
      try: readLine(stdin)
      except IOError: ""
      except EOFError: ""
    if line.len == 0 and isAtty(stdin) == false:
      break
    let alive = dispatch(session, line)
    if not alive: break
