# netcrypt
A library for OpenComputers that facilitates the creation of encrypted communication channels between applications.

## Methods
| Method | Returns | Description |
| :---:  | :---:   | :---        |
|open(addr, port, [clientPreferredParameters])| Object | Opens a connection to a listening socket |
|listen(port, [serverAllowedParameters])| Object | Creates a socket and waits for a peer to connect |
|read()| number, string, or table | Decrypt and return data from the stream |
|write(data)| nil | Encrypt and write data to the stream |
|close()| nil | Destroy the socket and close the communication channel |

## Security Considerations
As this software deals heavily on the subject of data security and privacy, it is paramount to be aware of the exact security guarantees this software provides. The software provides the following three (3) guarantees:

* The connection is private. An adversary is unable to read the contents of messages transferred by this software.

* Messages are non-repudiable. The plaintext in each message is signed then encrypted, and the resulting ciphertext is signed again. By doing this, the receiver knows that the sender is the one who originally wrote the message, and the sender is the one who encrypted the message.

* Message integrity is maintained. An adversary is unable to alter the contents of messages without alerting one of the communicating peers to the change.

## Examples
An example of connecting to a socket and reading data.
```
local netcrypt = require("netcrypt")

local mySocket = netcrypt.open("my_peer", 9999)

local data = mySocket:read()

print(data)

mySocket:close()
```

An example of connecting to a socket and writing data.
```
local netcrypt = require("netcrypt")

local mySocket = netcrypt.open("my_peer", 9999)

mySocket:write("Hello world")

mySocket:close()
```

An example of a script that continuously reads data from the socket until the user sends a CTRL-C interrupt.
```
local event    = require("event")
local netcrypt = require("netcrypt")
local data
local mysocket
local stopbit = 0

mysocket = netcrypt.listen(9999)

local eventInterruptID = event.listen("interrupted", function()
  stopbit = 1
  print("closing")
  mysocket:close()
end)

while stopbit == 0 do
  data = mysocket:read()
  print(data)
end

mysocket = nil
```

Similarly, a script that writes to the socket until encountering an interrupt.
```
local event    = require("event")
local netcrypt = require("netcrypt")
local mysocket
local stopbit = 0

mysocket = netcrypt.open("my_peer", 9999)

local eventInterruptID = event.listen("interrupted", function()
  stopbit = 1
  print("closing")
  mysocket:close()
end)

while stopbit == 0 do
  mysocket:write("hello world")
  os.sleep(1)
end

mysocket = nil
```

An example of connecting to a socket using user-specified parameters.
```
local netcrypt = require("netcrypt")

local mySocket = netcrypt.open("my_peer", 9999, {[1] = 256}, {[1] = "sha"}, {[1] = true})

...
```

An example of creating a socket using user-specified parameters.
```
local netcrypt = require("netcrypt")

local mySocket = netcrypt.listen(9999, {[1] = 256}, {[1] = "sha"}, {[1] = true})

...
```

### Optional Parameters
When connecting to or creating a socket, you may optionally pass some parameter options. These options include the encryption key size, hashing algorithm, and whether or not data should be compressed. The last two examples above demonstrated setting these parameters. What follows is a complete list of parameter options:
| Table 1 - Key Size | Table 2 - Hashing Algorithm | Table 3 - Use Compression |
| :---    | :---    | :---    |
| {[1] = 256, [2] = 384} | {[1] = "sha", [2] = "md5"} | {[1] = true, [2] = false} |

You may switch the values in the first and second keys in any combination that you wish, without of course editing the numeric key value itself. While both ends of the connection do not need to have the same order of values, both ends MUST have one common value in each table. For example, if a peer connects to a socket with `open("mypeer", 9999, {[1] = 256}, {[1] = "sha", [2] = "md5"}, {[1] = true, [2] = false})` and the socket is created with `listen(9999, {[1] = 384}, {[1] = "sha", [2] = "md5"}, {[1] = true, [2] = false})`, then the peers will refuse to connect. Because the peer who is connecting to the socket wants to use an encryption key of 256 bits, but the peer who created the socket will only agree upon an encryption key that is 384 bits.

All references to "sha" refers to sha256.
