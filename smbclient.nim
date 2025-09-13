import ./smb/smb

import std/[terminal, strutils, sequtils]

when isMainModule:
  let client = newSmbClient("0.0.0.0")
  try:
    # Connect with password
     client.connect("user", password = "P@ssw0rd!123")
    # Or with NTLM hash
     #client.connect("user", ntlmHash = "8846F7EAEE8FB117AD06BDD830B7586C")
    
     let shares = client.listShares()
     echo """ _   _ _                            _        _      ____ _ _            _   
| \ | (_)_ __ ___  _ __   __ _  ___| | _____| |_   / ___| (_) ___ _ __ | |_ 
|  \| | | '_ ` _ \| '_ \ / _` |/ __| |/ / _ \ __| | |   | | |/ _ \ '_ \| __|
| |\  | | | | | | | |_) | (_| | (__|   <  __/ |_  | |___| | |  __/ | | | |_ 
|_| \_|_|_| |_| |_| .__/ \__,_|\___|_|\_\___|\__|  \____|_|_|\___|_| |_|\__|
                  |_|                                                       """     
     # Find max length (dividing by 2 for UTF-16LE)
     var maxLen = 10
     for share in shares:
       let charCount = share.name.len div 2  # UTF-16LE uses 2 bytes per char
       if charCount > maxLen:
         maxLen = charCount
     
     let descCol = maxLen + 5
     
     echo "Share Name" & " ".repeat(descCol - "Share Name".len) & "Description"
     echo "-".repeat(descCol + 40)
     
     for share in shares:
       # Write the share name as-is (will display correctly if terminal handles UTF-16LE)
       stdout.setForegroundColor(fgCyan)
       stdout.write share.name
       stdout.resetAttributes()
       
       # Calculate padding based on character count, not byte count
       let charCount = share.name.len div 2
       let spaces = descCol - charCount
       stdout.write " ".repeat(spaces)
       
       if share.description.len > 0:
         stdout.write share.description
       stdout.write "\n"
  except: echo "[-] Error: ", getCurrentExceptionMsg()
  finally: client.disconnect()

                                         
