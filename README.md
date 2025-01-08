# Nimpacket
The start of an SMB library written in Nim. Lots of things need to be improved. Lots of things need to be tested. Lots of things need to be implemented. Expect bugs. Expect breaking changes. This is anything, but, a stable project. PRs are, of course, welcome!

## Usage
Add the line `import ./smb` into your program. For now, that's it. The SMB folder here imports the others, so you shouldn't need to do so manually. This will eventually change as more functionality is added.

I've tried to make things fairly simple, but this is SMB. You *do* need to know what you're doing.

There are "builder" functions for several SMB Requests (NEGOTIATE, SESSION_SETUP, CREATE, WRITE, READ, IOCTL). These all follow the same pattern for naming purposes: "*new*" SMB Request "*request*". e.g `newWriteRequest()`
Following this, should you need to modify any of the request types' (or SMB Headers') properties, you can do so. Most of these properties have default values, however, this does **not** mean you can expect things to work without changing anything. To keep things simple, most of the field names are very similar to what you will find on MSDN. e.g `SMB2NegotiateRequest.dialectCount`
Next, you'll need to serialize the data. There is a `build()` function for this purpose. Likewise, there is a `send()` function to send the request to the server. The `send()` returns the server's response status code and response as well.

Alternatively: You have full access to the underlying structures to do with as you please. 

The best sample code to understand this library is in *smbclient.nim*. 

At a *very* high level, it does the following:
- Sends SMB Negotiate Request
- Sends initial SMB Session Setup Request
- Sends *secondary* SMB Session Setup Request with NTLMv2 Response to Server's Challenge Message
- Sends SMB Tree Connect Request to connect to IPC$ share
- Sends SMB Create Request to open a handle to SRVSVC named pipe
- Sends SMB Write Request
- Sends SMB Read Request
- Sends SMB IOCTL Request to call a remote function (better known as RPC) 

Keep in mind, however, MSRPC is also in use here at some layers. SMB is merely a transport encapsulating those packets.

```nim
import ./smb/smb

when isMainModule:
  let client = newSmbClient("0.0.0.0")
  try:
    # Connect with password
     client.connect("user", password = "password")

    #[ Or with NTLM hash
     client.connect("user", ntlmHash = "8846F7EAEE8FB117AD06BDD830B7586C") ]#
    
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
```

## Supported Features
- SMB 2.0.2 and 2.1
- NTLMv2 Authentication (PTH accepted)

## To-do List
- Signing Support
- SMBv1 Support
- SMB 3.x Support
- NTLMv1 Authentication (the most likely to come any time soon)
- Kerberos Authentication
- NDR Encoder/Decoder
- ASN.1 BER Encoder/Decoder
