# netcrypt
A library for OpenComputers that facilitates the creation of encrypted communication channels between applications.

## Methods
| Name  | Returns | Description |
| :---: | :---:   | :---        |
|open(addr, port, [clientSupportedCiphers])| Object | Opens a connection to a listening socket |
|listen(port, [serverSupportedCiphers])| Object | Creates a socket and waits for a peer to connect |
|read()| string/table | Return decrypted data from the stream |
|write(data)| nil | Write data to the stream |
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

An example of creating a socket and reading/writing data.
```
local netcrypt = require("netcrypt")

local mySocket = netcrypt.listen(9999)

local data = mySocket:read()

mySocket:write("Hello world")

mySocket:close()
```

An example of connecting to a socket using custom cipher parameters.
```
local netcrypt = require("netcrypt")

local mySocket = netcrypt.open("my_peer", 9999, {[1] = 256}, {[1] = "sha"}, {[1] = true})

...
```

An example of creating a socket using custom cipher parameters.
```
local netcrypt = require("netcrypt")

local mySocket = netcrypt.listen(9999, {[1] = 256}, {[1] = "sha"}, {[1] = true})

...
```
