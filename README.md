# netcrypt
A library for OpenComputers that facilitates the creation of encrypted communication channels between applications.

## Methods
| Name  | Returns | Description |
| :---: | :---:   | :---        |
|open(addr, port, [clientPreferredParameters])| Object | Opens a connection to a listening socket |
|listen(port, [serverAllowedParameters])| Object | Creates a socket and waits for a peer to connect |
|read()| string or table | Decrypt and return data from the stream |
|write(data)| nil | Encrypt and write data to the stream |
|close()| nil | Destroy the socket and close the communication channel |

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
When opening or creating a socket, you can optionally pass some parameter options. These options include the encryption key size, hashing algorithm, and whether or not data should be compressed. The last two examples above depicted setting these parameters. Notice that each setting is within its own table. The following table shows the complete list of parameter options:
| Table 1 - Key Size | Table 2 - Hashing Algorithm | Table 3 - Use Compression |
| :---    | :---    | :---    |
| {[1] = 256, [2] = 384} | {[1] = "sha", [2] = "md5"} | {[1] = true, [2] = false} |

You may switch the values in the first and second keys in any combination that you wish, without of course editing the numeric key value itself. While both ends of the connection do not need to have the same order of values, both ends MUST have one common value in each table. For example, if a peer connects to a socket with `open("mypeer", 9999, {[1] = 256}, {[1] = "sha", [2] = "md5"}, {[1] = true, [2] = false})` and the socket is created with `listen(9999, {[1] = 384}, {[1] = "sha", [2] = "md5"}, {[1] = true, [2] = false})`, then the peers will refuse to connect. Because the peer who is connecting to the socket wants to use an encryption key of 256 bits, but the peer who created the socket will only agree upon an encryption key that is 384 bits.
