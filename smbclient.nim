import ./smb/smb

when isMainModule:
  let client = newSmbClient("0.0.0.0")
  try:
    # Connect with password
     client.connect("user", password = "password")
    # Or with NTLM hash
     #client.connect("user", ntlmHash = "8846F7EAEE8FB117AD06BDD830B7586C")
    
     let shares = client.listShares()
     echo "\nShare Name (Description)"
     echo "--------------------------"
     for share in shares:
      stdout.write share.name

      if share.description.len > 0:
        stdout.write "\t(", share.description, ")"
      stdout.write "\n"
  except: echo "[-] Error: ", getCurrentExceptionMsg()
  finally: client.disconnect()
