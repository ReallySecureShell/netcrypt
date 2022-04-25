local component = require("component")
local event     = require("event")
local minitel   = require("minitel")
local serial    = require("serialization")

--[=====[
The purpose of this library is to provide cryptographic functions for securing
network messages between two communicating parties. Netcrypt takes on some
qualities of the Transport Layer Security (TLS) protocol. With TLS 1.2 being
used as a reference, which is documented in Request For Comments (RFC) 5246.

MORE TO BE SAID HERE
--]=====]

-- Pre-defined variables and tables
local _
local timeout = 60

local libnetcrypt = {}
libnetcrypt.__index = libnetcrypt

-- Create component objects
-------------------------------------------------------------------------------
local _, datacard = xpcall(function()
                            -- Make sure that there is a Tier 3 Data Card
                            -- installed on the local computer.
                            if component.data.generateKeyPair() then
                                return component.data
                            end
                        end,
                        function(err)
                            return false
                        end)

-- Throw an exception if encountering an issue with the Data Card.
if not datacard then
    error("libnetcrypt: No Data Card installed, or installed Data Card is not of required tier. A Data Card (Tier 3) is required.")
end
-------------------------------------------------------------------------------

-- Helper functions
-------------------------------------------------------------------------------
-- stream, data, [keyMaterial-and-CipherSpec]
local function packetBuilder(stream, data, ...)
    local data = data
    local status
    if not ... then
        -- Perform initial serialization on the data.
        status, data = xpcall(function(d)
                                return serial.serialize(d)
                            end,
                            function(err)
                                return false
                            end, data)
        if not status then
            data = nil
            return false, "encode_error"
        end
        
        -- Generate a checksum of the message. The checksum will always be
        -- sha256 when no optional parameters are supplied.
        status, data = xpcall(function(d)
                                return {["checksum"] = datacard.sha256(d), ["data"] = d}
                            end,
                            function(err)
                                return false
                            end, data)
        if not status then
            data = nil
            return false, "internal_error"
        end
        
        -- Serialize the message again, this time with it containing the
        -- checksum.
        status, data = xpcall(function(d)
                                return serial.serialize(d)
                            end,
                            function(err)
                                return false
                            end, data)
        if not status then
            data = nil
            return false, "encode_error"
        end
        
        -- Write the message to the socket.
        status, _ = xpcall(function(d)
                            stream:write(d)
                        end,
                        function(err)
                            return false
                        end, data)
        if not status then
            data = nil
            return false, "transmission_failure"
        end
        
        data = nil
        return true, ""
    else
        local encryptionMaterial = { ... }
        
        -- Perform initial serialization on the data.
        status, data = xpcall(function(d)
                                return serial.serialize(d)
                            end,
                            function(err)
                                return false
                            end, data)
        if not status then
            data = nil
            encryptionMaterial = nil
            return false, "encode_error"
        end
        
        -- If compression was negotiated during the handshake, compress the
        -- message before encrypting. This might make the application
        -- vulnerable to the CRIME attack (https://en.wikipedia.org/wiki/CRIME)
        if encryptionMaterial[4] == true then
            status, data = xpcall(function(d)
                                    return datacard.deflate(d)
                                end,
                                function(err)
                                    return false
                                end, data)
            if not status then
                data = nil
                encryptionMaterial = nil
                return false, "compression_error"
            end
        end
        
        -- Encrypt the data.
        status, data = xpcall(function(d)
                                return datacard.encrypt(d, encryptionMaterial[1], encryptionMaterial[2])
                            end,
                            function(err)
                                return false
                            end, data)
        if not status then
            data = nil
            encryptionMaterial = nil
            return false, "encrypt_error"
        end
        
        -- Generate a checksum of the encrypted material.
        status, data = xpcall(function(d)
                                if encryptionMaterial[3] == "sha" then
                                    return {["checksum"] = datacard.sha256(d), ["data"] = d}
                                elseif encryptionMaterial[3] == "md5" then
                                    return {["checksum"] = datacard.md5(d), ["data"] = d}
                                end
                            end,
                            function(err)
                                return false
                            end, data)
        if not status then
            data = nil
            encryptionMaterial = nil
            return false, "internal_error"
        end
        
        -- Serialize the data again before transmission.
        status, data = xpcall(function(d)
                                return serial.serialize(d)
                            end,
                            function(err)
                                return false
                            end, data)
        if not status then
            data = nil
            encryptionMaterial = nil
            return false, "encode_error"
        end
        
        -- Write the message to the socket.
        status, data = xpcall(function(d)
                                return stream:write(d)
                            end,
                            function(err)
                                return false
                            end, data)
        if not status then
            data = nil
            encryptionMaterial = nil
            return false, "transmission_failure"
        end
        
        data = nil
        encryptionMaterial = nil
        return true, ""
    end
end

-- Perform operations to recover the original network message.
local function packetDeconstructor(data, ...)
    local data = data
    local status
    if not ... then
        -- Unserialize the initial message.
        status, data = xpcall(function(d)
                                return serial.unserialize(d)
                            end,
                            function(err)
                                return false
                            end, data)
        if not status then
            data = nil
            return false, "decode_error", ""
        end
        
        -- Verify the integrity of the message by comparing checksums.
        -- Notice, the hash algorithm is always sha256 when no parameters are
        -- supplied.
        status, _ = xpcall(function(d)
                            if datacard.sha256(d["data"]) ~= d["checksum"] then
                                error()
                            else
                                return true
                            end
                        end,
                        function(err)
                            return false
                        end, data)
        if not status then
            data = nil
            return false, "bad_checksum", ""
        end
        
        -- Unserialize the data portion of the message.
        status, data["data"] = xpcall(function(d)
                                        return serial.unserialize(d["data"])
                                    end,
                                    function(err)
                                        return false
                                    end, data)
        if not status then
            data = nil
            return false, "decode_error", ""
        end
        
        return true, "", data
    else
        local encryptionMaterial = { ... }
        
        -- Unserialize the initial message.
        status, data = xpcall(function(d)
                                return serial.unserialize(d)
                            end,
                            function(err)
                                return false
                            end, data)
        if not status then
            data = nil
            encryptionMaterial = nil
            return false, "decode_error", ""
        end
        
        -- Verify the integrity of the message by comparing checksums.
        status, _ = xpcall(function(d)
                            if encryptionMaterial[3] == "sha" then
                                if datacard.sha256(d["data"]) ~= d["checksum"] then
                                    error()
                                else
                                    return true
                                end
                            elseif encryptionMaterial[3] == "md5" then
                                if datacard.md5(d["data"]) ~= d["checksum"] then
                                    error()
                                else
                                    return true
                                end
                            end
                        end,
                        function(err)
                            return false
                        end, data)
        if not status then
            data = nil
            encryptionMaterial = nil
            return false, "bad_checksum", ""
        end
        
        -- Decrypt the data.
        status, data["data"] = xpcall(function(d)
                                        return datacard.decrypt(d["data"], encryptionMaterial[1], encryptionMaterial[2])
                                    end,
                                    function(err)
                                        return false
                                    end, data)
        if not status then
            data = nil
            encryptionMaterial = nil
            return false, "decrypt_error", ""
        end
        
        -- Decompress if compression was negotiated.
        if encryptionMaterial[4] == true then
            status, data["data"] = xpcall(function(d)
                                            return datacard.inflate(d["data"])
                                        end,
                                        function(err)
                                            return false
                                        end, data)
            if not status then
                data = nil
                encryptionMaterial = nil
                return false, "decompression_error", ""
            end
        end
        
        -- Unserialize the data portion of the message.
        status, data["data"] = xpcall(function(d)
                                        return serial.unserialize(d["data"])
                                    end,
                                    function(err)
                                        return false
                                    end, data)
        if not status then
            data = nil
            encryptionMaterial = nil
            return false, "decode_error", ""
        end
        
        encryptionMaterial = nil
        return true, "", data
    end
end

local ALERT = {
    ["bad_certificate"]       = function(stream, ...) _, _ = packetBuilder(stream, {[1] = "FATAL", [2] = "BAD_CERTIFICATE"}, ...) end, -- A certificate was corrupt in some way.
    ["bad_checksum"]          = function(stream, ...) _, _ = packetBuilder(stream, {[1] = "FATAL", [2] = "BAD_CHECKSUM"}, ...) end, -- When comparing the checksums of the sent and received message, the checksums did not match.
    ["bad_record"]            = function(stream, ...) _, _ = packetBuilder(stream, {[1] = "FATAL", [2] = "BAD_RECORD"}, ...) end, -- A message had an different hash value than the expected hash value.
    ["close_notify"]          = function(stream, ...) _, _ = packetBuilder(stream, {[1] = "FATAL", [2] = "CLOSE_NOTIFY"}, ...) end, -- Not an error, but the stream must close immediately.
    ["compression_error"]     = function(stream, ...) _, _ = packetBuilder(stream, {[1] = "FATAL", [2] = "COMPRESSION_ERROR"}, ...) end, -- The data was unable to be compressed due to an error.
    ["decode_error"]          = function(stream, ...) _, _ = packetBuilder(stream, {[1] = "FATAL", [2] = "DECODE_ERROR"}, ...) end, -- When deserialization fails.
    ["decompression_error"]   = function(stream, ...) _, _ = packetBuilder(stream, {[1] = "FATAL", [2] = "DECOMPRESSION_ERROR"}, ...) end, -- A message was unable to be decompressed.
    ["decrypt_error"]         = function(stream, ...) _, _ = packetBuilder(stream, {[1] = "FATAL", [2] = "DECRYPT_ERROR"}, ...) end, -- The message was unable to be decrypted.
    ["encode_error"]          = function(stream, ...) _, _ = packetBuilder(stream, {[1] = "FATAL", [2] = "ENCODE_ERROR"}, ...) end, -- An error occurred while attempting to serialize the data.
    ["encrypt_error"]         = function(stream, ...) _, _ = packetBuilder(stream, {[1] = "FATAL", [2] = "ENCRYPT_ERROR"}, ...) end, -- Encryption of data failed.
    ["handshake_failure"]     = function(stream, ...) _, _ = packetBuilder(stream, {[1] = "FATAL", [2] = "HANDSHAKE_FAILURE"}, ...) end, -- An error of some kind relating to the handshake occurred.
    ["internal_error"]        = function(stream, ...) _, _ = packetBuilder(stream, {[1] = "FATAL", [2] = "INTERNAL_ERROR"}, ...) end, -- An error unrelated to the protocol has occurred.
    ["msg_ok"]                = function(stream, ...) _, _ = packetBuilder(stream, {[1] = "OK",    [2] = "MSG_OK"}, ...) end, -- The peer sent a message that did not result in any error(s) occurring. The message content itself may be a fatal message, however the message was able to be deconstructed successfully.
    ["resend"]                = function(stream, ...) _, _ = packetBuilder(stream, {[1] = "WARN",  [2] = "RESEND"}, ...) end, -- The peer sent a message that had a bad_checksum, as a result, the peer is asked to resend the message.
    ["transmission_failure"]  = function(stream, ...) _, _ = packetBuilder(stream, {[1] = "FATAL", [2] = "TRANSMISSION_FAILURE"}, ...) end, -- An error occurred while attempting to send the message.
    ["unexpected_message"]    = function(stream, ...) _, _ = packetBuilder(stream, {[1] = "FATAL", [2] = "UNEXPECTED_MESSAGE"}, ...) end, -- The peer sent a message that does not conform to the standard formatting of messages in this protocol.
}
-------------------------------------------------------------------------------

function libnetcrypt.open(peerAddress, port, ...)
    checkArg(1, peerAddress, "string")
    checkArg(2, port, "number")
    
    -- Is used through the rest of the session.
    local digestAlgorithm        = nil
    local internalReadEventName  = nil
    local internalWriteEventName = nil
    local isCompressed           = nil
    local iv                     = nil
    local keySize                = nil
    local localPrivateKey        = nil
    local localPublicKey         = nil
    local masterSecret           = nil
    local peerPublicKey          = nil
    local stream                 = nil
    -- Is only used within the handshake.
    local clientFinishedTable    = nil
    local clientSupportedCiphers = nil
    local errmsg                 = nil
    local orderOfExpectedHandshakeMessagesFromServer = nil
    local status                 = nil
    
    if not ... then
        clientSupportedCiphers = {
            ["keySizes"]         = {[1] = 256,   [2] = 384},
            ["digestAlgorithms"] = {[1] = "sha", [2] = "md5"},
            ["useCompression"]   = {[1] = true,  [2] = false},
        }
    else
        clientSupportedCiphers = {}
        status, errmsg = xpcall(function(tArgs)
                                -- Ensure the user-provided parameters contains
                                -- exactly three (3) tables.
                                if #tArgs ~= 3 then
                                    error("invalid amount of parameters provided (expected 3, got "..#tArgs..")")
                                end
                                
                                for key, tbl in pairs(tArgs) do
                                    -- Ensure that the table contains no-more-than two (2) items, and no fewer-than one (1) item.
                                    if #tbl < 1 or #tbl > 2 then
                                        error("invalid amount of parameters provided for table #"..key.." (expected 1 or 2, got "..#tbl..")")
                                    end
                                    -- Check all values within all the user-provided tables, ensure
                                    -- tables contain the correct information i.e. all values are of
                                    -- the correct type, and that each table contains the known values.
                                    if key == 1 then -- Proper formatting: {[1] = 256, [2] = 384}
                                        for indexOfItem, valueOfItem in pairs(tbl) do -- 'Pairs' because an erroneous table may not contain only number indexes.
                                            -- First, verify that the index (indexOfItem) is an integer, since that is how we will be calling the items from
                                            -- these tables.
                                            if type(indexOfItem) ~= "number" then
                                                error("bad key in table #1 (number expected, got "..type(indexOfItem)..")")
                                            -- Next, verify that the value of the item (valueOfItem) is of the correct type.
                                            elseif type(valueOfItem) ~= "number" then
                                                error("bad value in table #1 (number expected, got "..type(valueOfItem)..")")
                                            -- Finally, verify that the value of the item (valueOfItem) is of a valid value,
                                            -- this case, a valid value is 256 or 384.
                                            elseif valueOfItem ~= 256 and valueOfItem ~= 384 then
                                                error("bad value in table #1 (number value of 256 or 384 expected)")
                                            end
                                        end
                                        clientSupportedCiphers["keySizes"] = tbl
                                    elseif key == 2 then -- Proper formatting: {[1] = "sha", [2] = "md5"}
                                        for indexOfItem, valueOfItem in pairs(tbl) do
                                            if type(indexOfItem) ~= "number" then
                                                error("bad key in table #2 (number expected, got "..type(indexOfItem)..")")
                                            elseif type(valueOfItem) ~= "string" then
                                                error("bad value in table #2 (string expected, got "..type(valueOfItem)..")")
                                            elseif valueOfItem ~= "sha" and valueOfItem ~= "md5" then
                                                error("bad value in table #2 (string value of 'sha' or 'md5' expected)")
                                            end
                                        end
                                        clientSupportedCiphers["digestAlgorithms"] = tbl
                                    elseif key == 3 then -- Proper formatting: {[1] = true, [2] = false}
                                        for indexOfItem, valueOfItem in pairs(tbl) do
                                            if type(indexOfItem) ~= "number" then
                                                error("bad key in table #3 (number expected, got "..type(indexOfItem)..")")
                                            elseif type(valueOfItem) ~= "boolean" then
                                                error("bad value in table #3 (boolean expected, got "..type(valueOfItem)..")")
                                            end
                                            -- No other checks are required, because if the values are boolean, the values
                                            -- can only ever be true and false.
                                        end
                                        clientSupportedCiphers["useCompression"] = tbl
                                    end
                                end
                            end,
                            function(err)
                                return err
                            end, { ... })
        
        if not status then
            error(errmsg)
        end
    end

    -- CLIENT HANDSHAKE
    ---------------------------------------------------------------------------
    local data
    local function clearHandshakeData(s)
        -- Close the minitel socket.
        s:close() -- s = stream
        -- Is used through the rest of the session.
        digestAlgorithm        = nil
        isCompressed           = nil
        iv                     = nil
        keySize                = nil
        localPrivateKey        = nil
        localPublicKey         = nil
        masterSecret           = nil
        peerPublicKey          = nil
        stream                 = nil
        -- Is only used within the handshake.
        clientFinishedTable    = nil
        clientSupportedCiphers = nil
        orderOfExpectedHandshakeMessagesFromServer = nil
        status                 = nil
    end
    
    -- Ordered from last to first.
    orderOfExpectedHandshakeMessagesFromServer = {
        [1] = "SERVER_FINISHED",
        [2] = "SERVER_KEY_SHARE",
        [3] = "SERVER_SELECTED_CIPHERS",
        [4] = "SERVER_HELLO",
    }
    
    stream = minitel.open(peerAddress, port) -- Automatically closes stream when no peer has connected in n amount of time. This is apart of minitel.
    
    -- Send CLIENT_HELLO message
    status, errmsg = packetBuilder(stream, {[1] = "CLIENT_HELLO", [2] = ""})
    
    if not status then
        ALERT[errmsg](stream)
        clearHandshakeData(stream)
        error(string.upper(errmsg))
    end
    
    -- Between sending the CLIENT_HELLO message and when we start
    -- event.pull to look for the server's response is a race-condition.
    -- There may be certain instances where we miss the server's response.
    repeat
        -- The handshake will timeout if data from the expected peer has not
        -- been received in amount of seconds specified by 'timeout'.
        _, _, _, data = event.pull(timeout, "net_msg", peerAddress, stream.port, nil) -- Remember to create a condition for if the timeout is reached.
        
        -- This pertains to the last part of the handshake, the FINISHED
        -- message. This is where the handshake becomes encrypted, and
        -- therefore requires additional processing to recover the
        -- original message.
        if orderOfExpectedHandshakeMessagesFromServer[#orderOfExpectedHandshakeMessagesFromServer] == "SERVER_FINISHED" then
            status, errmsg, data = packetDeconstructor(data, masterSecret, iv, digestAlgorithm, isCompressed)
            if not status then
                ALERT[errmsg](stream)
                clearHandshakeData(stream)
                error(string.upper(errmsg))
            end
        -- Before the FINISHED message, deconstruct packets without
        -- encryption and without the chosen ciphersuite.
        else
            status, errmsg, data = packetDeconstructor(data)
            if not status then
                ALERT[errmsg](stream)
                clearHandshakeData(stream)
                error(string.upper(errmsg))
            end
        end
        
        -- If receiving a fatal message, clear all handshake variables and
        -- exit with an error, followed by the alert message. The errors
        -- come from the server, so it is either a response to something sent by
        -- the client, or an error on the server's end. That said, when the
        -- server gives an fatal response, it is handled directly below.
        if data["data"][1] == "FATAL" then
            clearHandshakeData(stream)
            error(data["data"][2])
        else
            -- The first item in the 'data' table indicates the type of handshake
            -- message. If the received handshake message is equal to the string in
            -- the last key inside of the
            -- 'orderOfExpectedHandshakeMessagesFromServer' table, we know that is
            -- the current step of the handshake, and we need to process that data.
            if data["data"][1] == orderOfExpectedHandshakeMessagesFromServer[#orderOfExpectedHandshakeMessagesFromServer] then
                if data["data"][1] == "SERVER_HELLO" then
                    -- Send client 'chosen' ciphers. At this time, there is no plans to have a cipher negotiation sub-protocol. YOU MUST know the ciphersuite of the server before connecting.
                    -- However, the default ciphersuite for the client/server is the same, which is balanced for security and speed.
                    status, errmsg = packetBuilder(stream, {[1] = "CLIENT_SELECTED_CIPHERS", [2] = clientSupportedCiphers})
                    if not status then
                        ALERT[errmsg](stream)
                        clearHandshakeData(stream)
                        error(string.upper(errmsg))
                    end
                    table.remove(orderOfExpectedHandshakeMessagesFromServer, #orderOfExpectedHandshakeMessagesFromServer)
                elseif data["data"][1] == "SERVER_SELECTED_CIPHERS" then
                    -- Set the chosen ciphersuite.
                    keySize         = data["data"][2].keySize
                    digestAlgorithm = data["data"][2].digestAlgorithm
                    isCompressed    = data["data"][2].isCompressed
                    table.remove(orderOfExpectedHandshakeMessagesFromServer, #orderOfExpectedHandshakeMessagesFromServer)
                elseif data["data"][1] == "SERVER_KEY_SHARE" then
                    -- Rebuild the public key object from the server.
                    status, peerPublicKey = xpcall(function()
                                                    return datacard.deserializeKey(data["data"][2].serverPublicKey, "ec-public")
                                                end,
                                                function(err)
                                                    return false
                                                end)
                    -- If deserializing the server's public key failed,
                    -- then send a 'BAD_CERTIFICATE' alert and close the
                    -- session.
                    if not status then
                        ALERT["bad_certificate"](stream)
                        clearHandshakeData(stream)
                        error("BAD_CERTIFICATE")
                    end
                    
                    -- The server-generated initialization vector.
                    iv = data["data"][2].iv
                    
                    -- Generate asymmetric keypair, then send the public key to the server.
                    localPublicKey, localPrivateKey = datacard.generateKeyPair(keySize)
                    
                    -- Generate the Diffie-Hellman shared key. It is always represented as a
                    -- md5 hash, regardless of the chosen ciphersuite.
                    masterSecret = datacard.md5(datacard.ecdh(localPrivateKey, peerPublicKey))
                    
                    -- Send client public key to server.
                    status, errmsg = packetBuilder(stream, {[1] = "CLIENT_KEY_SHARE", [2] = {["clientPublicKey"] = localPublicKey.serialize()}})
                    
                    if not status then
                        ALERT[errmsg](stream)
                        clearHandshakeData(stream)
                        error(string.upper(errmsg))
                    end
                    
                    -- Send the 'CLIENT_FINISHED' message. All information that the client
                    -- sent to the server is repeated over an encrypted connection.
                    clientFinishedTable = {
                    [1] = "CLIENT_FINISHED",
                    [2] = {
                            ["CLIENT_SELECTED_CIPHERS"] = clientSupportedCiphers,
                            ["CLIENT_KEY_SHARE"] = {["clientPublicKey"] = localPublicKey.serialize()},
                          }
                    }
                    status, errmsg = packetBuilder(stream, clientFinishedTable, masterSecret, iv, digestAlgorithm, isCompressed)
                    
                    if not status then
                        ALERT[errmsg](stream)
                        clearHandshakeData(stream)
                        error(string.upper(errmsg))
                    end
                    table.remove(orderOfExpectedHandshakeMessagesFromServer, #orderOfExpectedHandshakeMessagesFromServer)
                elseif data["data"][1] == "SERVER_FINISHED" then
                    status, _ = xpcall(function()
                                        if data["data"][2].SERVER_SELECTED_CIPHERS.keySize ~= keySize then
                                            error()
                                        elseif data["data"][2].SERVER_SELECTED_CIPHERS.digestAlgorithm ~= digestAlgorithm then
                                            error()
                                        elseif data["data"][2].SERVER_SELECTED_CIPHERS.isCompressed ~= isCompressed then
                                            error()
                                        elseif data["data"][2].SERVER_KEY_SHARE.serverPublicKey ~= peerPublicKey.serialize() then
                                            error()
                                        elseif data["data"][2].SERVER_KEY_SHARE.iv ~= iv then
                                            error()
                                        else
                                            return true
                                        end
                                    end,
                                    function(err)
                                        return false
                                    end)
                    if not status then
                        ALERT["bad_record"](stream, masterSecret, iv, digestAlgorithm, isCompressed)
                        clearHandshakeData(stream)
                        error("BAD_RECORD")
                    end
                    table.remove(orderOfExpectedHandshakeMessagesFromServer, #orderOfExpectedHandshakeMessagesFromServer)
                end
            else
                ALERT["unexpected_message"](stream)
                clearHandshakeData(stream)
                error("UNEXPECTED_MESSAGE")
            end
        end
    until(#orderOfExpectedHandshakeMessagesFromServer == 0)
    
    -- An error message can be sent by the peer after the handshake has
    -- finished. So we wait for a network message from the peer for three
    -- seconds before continuing.
    _, _, _, data = event.pull(3, "net_msg", peerAddress, stream.port, nil)
    
    -- An encrypted message is expected at this point.
    status, errmsg, data = packetDeconstructor(data, masterSecret, iv, digestAlgorithm, isCompressed)
    
    if data == "" then
        -- Do nothing
    elseif data["data"][1] == "FATAL" then
        clearHandshakeData(stream)
        error(data["data"][2])
    end
    
    -- Clear variables that are only used during the handshake.
    clientFinishedTable    = nil
    clientSupportedCiphers = nil
    data                   = nil
    errmsg                 = nil
    orderOfExpectedHandshakeMessagesFromServer = nil
    status                 = nil
    ---------------------------------------------------------------------------
    
    internalReadEventName = "readEvent_"..peerAddress.."_"..port
    internalReadEventName, _ = internalReadEventName:gsub('-','_')
    
    internalWriteEventName = "writeEvent_"..peerAddress.."_"..port
    internalWriteEventName, _ = internalWriteEventName:gsub('-','_')
    
    return setmetatable({
        state  = "open";
        stream = stream;
        sessionHandleIncomingNetworkMessagesEventID = nil;
        internalReadEventName  = internalReadEventName;
        internalWriteEventName = internalWriteEventName;
        sessionRecord = {
            digestAlgorithm = digestAlgorithm,
            isCompressed    = isCompressed,
            iv              = iv,
            keySize         = keySize,
            localPrivateKey = localPrivateKey,
            localPublicKey  = localPublicKey,
            masterSecret    = masterSecret,
            peerAddress     = peerAddress,
            peerPublicKey   = peerPublicKey,
            port            = port,
        };
    }, libnetcrypt)
end

-- Debugging
-- local foo = libnetcrypt.open("AE-PLC", 9999, {[1] = 256}, {[1] = "sha"}, {[1] = true})

function libnetcrypt.listen(port, ...)
    checkArg(1, port, "number")
    
    -- Is used through the rest of the session.
    local digestAlgorithm        = nil
    local internalReadEventName  = nil
    local internalWriteEventName = nil
    local isCompressed           = nil
    local iv                     = nil
    local keySize                = nil
    local localPrivateKey        = nil
    local localPublicKey         = nil
    local masterSecret           = nil
    local peerAddress            = nil
    local peerPublicKey          = nil
    local stream                 = nil
    -- Is only used within the handshake.
    local errmsg                 = nil
    local initialClientSelectedCiphers = nil
    local orderOfExpectedHandshakeMessagesFromClient = nil
    local serverFinishedTable    = nil
    local serverSupportedCiphers = nil
    local status                 = nil
    
    if not ... then
        serverSupportedCiphers = {
            ["keySizes"]         = {[1] = 256,   [2] = 384},
            ["digestAlgorithms"] = {[1] = "sha", [2] = "md5"},
            ["useCompression"]   = {[1] = true,  [2] = false},
        }
    else
        serverSupportedCiphers = {}
        status, errmsg = xpcall(function(tArgs)
                                -- Ensure the user-provided parameters contains
                                -- exactly three (3) tables.
                                if #tArgs ~= 3 then
                                    error("invalid amount of parameters provided (expected 3, got "..#tArgs..")")
                                end
                                
                                for key, tbl in pairs(tArgs) do
                                    -- Ensure that the table contains no-more-than two (2) items, and no fewer-than one (1) item.
                                    if #tbl < 1 or #tbl > 2 then
                                        error("invalid amount of parameters provided for table #"..key.." (expected 1 or 2, got "..#tbl..")")
                                    end
                                    -- Check all values within all the user-provided tables, ensure
                                    -- tables contain the correct information i.e. all values are of
                                    -- the correct type, and that each table contains the known values.
                                    if key == 1 then -- Proper formatting: {[1] = 256, [2] = 384}
                                        for indexOfItem, valueOfItem in pairs(tbl) do -- 'Pairs' because an erroneous table may not contain only number indexes.
                                            -- First, verify that the index (indexOfItem) is an integer, since that is how we will be calling the items from
                                            -- these tables.
                                            if type(indexOfItem) ~= "number" then
                                                error("bad key in table #1 (number expected, got "..type(indexOfItem)..")")
                                            -- Next, verify that the value of the item (valueOfItem) is of the correct type.
                                            elseif type(valueOfItem) ~= "number" then
                                                error("bad value in table #1 (number expected, got "..type(valueOfItem)..")")
                                            -- Finally, verify that the value of the item (valueOfItem) is of a valid value,
                                            -- this case, a valid value is 256 or 384.
                                            elseif valueOfItem ~= 256 and valueOfItem ~= 384 then
                                                error("bad value in table #1 (number value of 256 or 384 expected)")
                                            end
                                        end
                                        serverSupportedCiphers["keySizes"] = tbl
                                    elseif key == 2 then -- Proper formatting: {[1] = "sha", [2] = "md5"}
                                        for indexOfItem, valueOfItem in pairs(tbl) do
                                            if type(indexOfItem) ~= "number" then
                                                error("bad key in table #2 (number expected, got "..type(indexOfItem)..")")
                                            elseif type(valueOfItem) ~= "string" then
                                                error("bad value in table #2 (string expected, got "..type(valueOfItem)..")")
                                            elseif valueOfItem ~= "sha" and valueOfItem ~= "md5" then
                                                error("bad value in table #2 (string value of 'sha' or 'md5' expected)")
                                            end
                                        end
                                        serverSupportedCiphers["digestAlgorithms"] = tbl
                                    elseif key == 3 then -- Proper formatting: {[1] = true, [2] = false}
                                        for indexOfItem, valueOfItem in pairs(tbl) do
                                            if type(indexOfItem) ~= "number" then
                                                error("bad key in table #3 (number expected, got "..type(indexOfItem)..")")
                                            elseif type(valueOfItem) ~= "boolean" then
                                                error("bad value in table #3 (boolean expected, got "..type(valueOfItem)..")")
                                            end
                                            -- No other checks are required, because if the values are boolean, the values
                                            -- can only ever be true and false.
                                        end
                                        serverSupportedCiphers["useCompression"] = tbl
                                    end
                                end
                            end,
                            function(err)
                                return err
                            end, { ... })
        
        if not status then
            error(errmsg)
        end
    end
    
    -- SERVER HANDSHAKE
    ---------------------------------------------------------------------------
    local data
    local function clearHandshakeData(s)
        -- Close the minitel socket.
        s:close()
        -- Is used through the rest of the session.
        digestAlgorithm        = nil
        isCompressed           = nil
        iv                     = nil
        keySize                = nil
        localPrivateKey        = nil
        localPublicKey         = nil
        masterSecret           = nil
        peerAddress            = nil
        peerPublicKey          = nil
        stream                 = nil
        -- Is only used within the handshake.
        initialClientSelectedCiphers = nil
        orderOfExpectedHandshakeMessagesFromClient = nil
        serverFinishedTable    = nil
        serverSupportedCiphers = nil
        status                 = nil
    end
    
    -- Ordered from last to first.
    orderOfExpectedHandshakeMessagesFromClient = {
        [1] = "CLIENT_FINISHED",
        [2] = "CLIENT_KEY_SHARE",
        [3] = "CLIENT_SELECTED_CIPHERS",
        [4] = "CLIENT_HELLO",
    }
    
    stream = minitel.listen(port)
    
    peerAddress = stream.addr
    
    repeat
        _, _, _, data = event.pull(timeout, "net_msg", peerAddress, stream.port, nil) -- Remember to create a condition for if the timeout is reached.
        
        -- This pertains to the last part of the handshake, the FINISHED
        -- message. This is where the handshake becomes encrypted, and
        -- therefore requires additional processing to recover the
        -- original message.
        if orderOfExpectedHandshakeMessagesFromClient[#orderOfExpectedHandshakeMessagesFromClient] == "CLIENT_FINISHED" then
            status, errmsg, data = packetDeconstructor(data, masterSecret, iv, digestAlgorithm, isCompressed)
            if not status then
                ALERT[errmsg](stream)
                clearHandshakeData(stream)
                error(string.upper(errmsg))
            end
        -- Before the FINISHED message, deconstruct packets without
        -- encryption and without the chosen ciphersuite.
        else
            status, errmsg, data = packetDeconstructor(data)
            if not status then
                ALERT[errmsg](stream)
                clearHandshakeData(stream)
                error(string.upper(errmsg))
            end
        end
        
        if data["data"][1] == "FATAL" then
            clearHandshakeData(stream)
            error(data["data"][2])
        else
            if data["data"][1] == orderOfExpectedHandshakeMessagesFromClient[#orderOfExpectedHandshakeMessagesFromClient] then
                if data["data"][1] == "CLIENT_HELLO" then
                    -- Send SERVER_HELLO message
                    status, errmsg = packetBuilder(stream, {[1] = "SERVER_HELLO", [2] = ""})
                    if not status then
                        ALERT[errmsg](stream)
                        clearHandshakeData(stream)
                        error(string.upper(errmsg))
                    end
                    table.remove(orderOfExpectedHandshakeMessagesFromClient, #orderOfExpectedHandshakeMessagesFromClient)
                elseif data["data"][1] == "CLIENT_SELECTED_CIPHERS" then
                    -- Select the ciphers that will be used.
                    --[=====[
                    The client, in reality, sends multiple ciphers to the server.
                    The server has dozens of ciphers it can choose from.
                    The server checks the clients ciphers against its own list of allowed
                    ciphers, if none of the ciphers sent by the client match
                    the ciphers allowed by the server, the server will terminate the
                    connection and respond with a HANDSHAKE_FAILURE alert message.
                    
                    In the case of OpenComputers, the server and client always have the
                    same capabilities, because of the Data Card installed in each.
                    In other words, when the client sends it's preferred cipher
                    to the server, the client is still functionally capable of
                    performing whatever cipher the server responds with.
                    However, the server has the final say in what cipher
                    will be used. If the client wants to use 256 bit encryption
                    keys, and the server only allows for 384 bit encryption keys
                    then the server will terminate the connection.
                    
                    If the client sends the following ciphers:
                    {
                        keySizes         = {[1] = 384,   [2] = 256},
                        digestAlgorithms = {[1] = "sha", [2] = "md5"},
                        useCompression   = {[1] = true,  [2] = false},
                    }
                    
                    And the server's allowed ciphers are:
                    {
                        keySizes         = {[1] = 256,   [2] = 384},
                        digestAlgorithms = {[1] = "sha", [2] = "md5"},
                        useCompression   = {[1] = true,  [2] = false},
                    }
                    
                    Then the server's selected ciphersuite will be:
                    {
                        keySize         = 256,
                        digestAlgorithm = "sha",
                        isCompressed    = true,
                    }
                    
                    The client and server both support the same keySizes,
                    digestAlgorithms, and compression parameters. However,
                    the client prefers to use a keysize of 384 over, 256
                    while the server prefers the opposite, a keysize of 256
                    over 384. Because the server prefers the key size to be 256
                    , 256 is chosen. This is because the parameters are chosen
                    on an order of priority, based on the order of items within
                    the table. A priority of 1 is the highest, which is the
                    first key in the table.
                    
                    If the client sends the following ciphers:
                    {
                        keySizes         = {[1] = 384},
                        digestAlgorithms = {[1] = "sha", [2] = "md5"},
                        useCompression   = {[1] = true,  [2] = false},
                    }
                    
                    And the server's allowed ciphers are:
                    {
                        keySizes         = {[1] = 256},
                        digestAlgorithms = {[1] = "sha", [2] = "md5"},
                        useCompression   = {[1] = true,  [2] = false},
                    }
                    
                    Then the server will respond with a HANDSHAKE_FAILURE alert
                    message, because the client chose a key size that the
                    server does not support.
                    --]=====]
                    
                    initialClientSelectedCiphers = data["data"][2]
                    
                    local breakLoop = 0
                    for sPriority, sValue in ipairs(serverSupportedCiphers["keySizes"]) do
                        for cPriority, cValue in ipairs(data["data"][2]["keySizes"]) do
                            if sValue == cValue then
                                keySize = sValue
                                breakLoop = 1
                                break
                            end
                        end
                        if breakLoop == 1 then
                            break
                        end
                    end
                    
                    breakLoop = 0
                    for sPriority, sValue in ipairs(serverSupportedCiphers["digestAlgorithms"]) do
                        for cPriority, cValue in ipairs(data["data"][2]["digestAlgorithms"]) do
                            if sValue == cValue then
                                digestAlgorithm = sValue
                                breakLoop = 1
                                break
                            end
                        end
                        if breakLoop == 1 then
                            break
                        end
                    end
                    
                    breakLoop = 0
                    for sPriority, sValue in ipairs(serverSupportedCiphers["useCompression"]) do
                        for cPriority, cValue in ipairs(data["data"][2]["useCompression"]) do
                            if sValue == cValue then
                                isCompressed = sValue
                                breakLoop = 1
                                break
                            end
                        end
                        if breakLoop == 1 then
                            break
                        end
                    end
                    breakLoop = nil
                    
                    if keySize == nil or digestAlgorithm == nil or isCompressed == nil then
                        ALERT["handshake_failure"](stream)
                        clearHandshakeData(stream)
                        error("HANDSHAKE_FAILURE")
                    end
                    
                    status, errmsg = packetBuilder(stream, {[1] = "SERVER_SELECTED_CIPHERS", [2] = {["keySize"] = keySize, ["digestAlgorithm"] = digestAlgorithm, ["isCompressed"] = isCompressed}})
                    
                    if not status then
                        ALERT[errmsg](stream)
                        clearHandshakeData(stream)
                        error(string.upper(errmsg))
                    end
                    
                    -- SERVER_KEY_SHARE --
                    
                    iv = datacard.random(16)
                    
                    localPublicKey, localPrivateKey = datacard.generateKeyPair(keySize)
                    
                    -- Send the server public key and IV to the client.
                    status, errmsg = packetBuilder(stream, {[1] = "SERVER_KEY_SHARE", [2] = {["serverPublicKey"] = localPublicKey.serialize(), ["iv"] = iv}})
                    
                    if not status then
                        ALERT[errmsg](stream)
                        clearHandshakeData(stream)
                        error(string.upper(errmsg))
                    end
                    table.remove(orderOfExpectedHandshakeMessagesFromClient, #orderOfExpectedHandshakeMessagesFromClient)
                elseif data["data"][1] == "CLIENT_KEY_SHARE" then
                    -- Rebuild the public key object from the server.
                    status, peerPublicKey = xpcall(function()
                                                    return datacard.deserializeKey(data["data"][2].clientPublicKey, "ec-public")
                                                end,
                                                function(err)
                                                    return false
                                                end)
                    -- If deserializing the client's public key failed,
                    -- then send a 'BAD_CERTIFICATE' alert and close the
                    -- session.
                    if not status then
                        ALERT["bad_certificate"](stream)
                        clearHandshakeData(stream)
                        error("BAD_CERTIFICATE")
                    end
                    
                    masterSecret = datacard.md5(datacard.ecdh(localPrivateKey, peerPublicKey))
                    table.remove(orderOfExpectedHandshakeMessagesFromClient, #orderOfExpectedHandshakeMessagesFromClient)
                elseif data["data"][1] == "CLIENT_FINISHED" then
                    status, _ = xpcall(function()
                                        if serial.serialize(data["data"][2].CLIENT_SELECTED_CIPHERS) ~= serial.serialize(initialClientSelectedCiphers) then
                                            error()
                                        elseif data["data"][2].CLIENT_KEY_SHARE.clientPublicKey ~= peerPublicKey.serialize() then
                                            error()
                                        else
                                            return true
                                        end
                                    end,
                                    function(err)
                                        return false
                                    end)
                    if not status then
                        ALERT["bad_record"](stream, masterSecret, iv, digestAlgorithm, isCompressed)
                        clearHandshakeData(stream)
                        error("BAD_RECORD")
                    end
                    
                    -- SERVER_FINISHED --
                    
                    serverFinishedTable = {
                    [1] = "SERVER_FINISHED",
                    [2] = {
                            ["SERVER_SELECTED_CIPHERS"] = {["keySize"] = keySize, ["digestAlgorithm"] = digestAlgorithm, ["isCompressed"] = isCompressed},
                            ["SERVER_KEY_SHARE"] = {["serverPublicKey"] = localPublicKey.serialize(), ["iv"] = iv},
                          }
                    }
                    status, errmsg = packetBuilder(stream, serverFinishedTable, masterSecret, iv, digestAlgorithm, isCompressed)
                    
                    if not status then
                        ALERT[errmsg](stream, masterSecret, iv, digestAlgorithm, isCompressed)
                        clearHandshakeData(stream)
                        error(string.upper(errmsg))
                    end
                    table.remove(orderOfExpectedHandshakeMessagesFromClient, #orderOfExpectedHandshakeMessagesFromClient)
                end
            else
                ALERT["unexpected_message"](stream)
                clearHandshakeData(stream)
                error("UNEXPECTED_MESSAGE")
            end
        end
    until(#orderOfExpectedHandshakeMessagesFromClient == 0)
    
    _, _, _, data = event.pull(3, "net_msg", peerAddress, stream.port, nil)
    
    status, errmsg, data = packetDeconstructor(data, masterSecret, iv, digestAlgorithm, isCompressed)
    
    if data == "" then
        -- Do nothing
    elseif data["data"][1] == "FATAL" then
        clearHandshakeData(stream)
        error(data["data"][2])
    end
    
    -- Clear variables that are only used during the handshake.
    data                   = nil
    errmsg                 = nil
    initialClientSelectedCiphers = nil
    orderOfExpectedHandshakeMessagesFromClient = nil
    serverFinishedTable    = nil
    serverSupportedCiphers = nil
    status                 = nil
    ---------------------------------------------------------------------------
    
    internalReadEventName = "readEvent_"..peerAddress.."_"..port
    internalReadEventName, _ = internalReadEventName:gsub('-','_')
    
    internalWriteEventName = "writeEvent_"..peerAddress.."_"..port
    internalWriteEventName, _ = internalWriteEventName:gsub('-','_')
    
    return setmetatable({
        state  = "open";
        stream = stream;
        sessionHandleIncomingNetworkMessagesEventID = nil;
        internalReadEventName  = internalReadEventName;
        internalWriteEventName = internalWriteEventName;
        sessionRecord = {
            digestAlgorithm = digestAlgorithm,
            isCompressed    = isCompressed,
            iv              = iv,
            keySize         = keySize,
            localPrivateKey = localPrivateKey,
            localPublicKey  = localPublicKey,
            masterSecret    = masterSecret,
            peerAddress     = peerAddress,
            peerPublicKey   = peerPublicKey,
            port            = port,
        };
    }, libnetcrypt)
end

-- Debugging
-- local bar = libnetcrypt.listen(9999, {[1] = 256}, {[1] = "sha"}, {[1] = true}) -- original

-- local bar = libnetcrypt.listen(9999, {[1] = 256, [2] = 256}, {[1] = "sha", [2] = "md5"}, {[1] = "true"}) -- Debugging

function libnetcrypt:incomingNetworkMessagesHandler(peerAddress, port, data)
    local errmsg = nil
    local status = nil
    
    if peerAddress == self.sessionRecord.peerAddress and port == self.stream.port and data == self.stream.sclose then
        -- Do nothing
    elseif peerAddress == self.sessionRecord.peerAddress and port == self.stream.port and data ~= self.stream.sclose then
        status, errmsg, data = packetDeconstructor(data, self.sessionRecord.masterSecret, self.sessionRecord.iv, self.sessionRecord.digestAlgorithm, self.sessionRecord.isCompressed)
        if not status then
            -- The peer sent a message whose hash did not match the provided hash within the message.
            -- Instead of telling the peer they sent a message with a bad checksum, ask the peer to
            -- resend the message.
            if errmsg == "bad_checksum" then
                ALERT["resend"](self.stream, self.sessionRecord.masterSecret, self.sessionRecord.iv, self.sessionRecord.digestAlgorithm, self.sessionRecord.isCompressed)
                event.push(self.internalReadEventName, "WARN", string.upper(errmsg))
            else
                self:close(errmsg)
            end
        else
            if data["data"][1] == "FATAL" then
                self:close(data["data"][2])
            elseif data["data"][1] == "WARN" then
                if data["data"][2] == "RESEND" then
                    event.push(self.internalWriteEventName, "WARN", "RESEND")
                end
            elseif data["data"][1] == "PEER_MSG" then
                ALERT["msg_ok"](self.stream, self.sessionRecord.masterSecret, self.sessionRecord.iv, self.sessionRecord.digestAlgorithm, self.sessionRecord.isCompressed)
                self.sessionRecord.iv = data["data"][3]
                event.push(self.internalReadEventName, "PEER_MSG", data["data"][2])
            elseif data["data"][1] == "OK" then
                if data["data"][2] == "MSG_OK" then
                    event.push(self.internalWriteEventName, "OK", "MSG_OK")
                end
            end
        end
    else
        -- Do nothing
    end
end

function libnetcrypt:read()
    local _       = nil
    local data    = nil
    local msgType = nil
    
    local function x(_, peerAddress, port, data)
        self:incomingNetworkMessagesHandler(peerAddress, port, data)
    end
    
    if not self.sessionHandleIncomingNetworkMessagesEventID and self.state == "open" then
        self.sessionHandleIncomingNetworkMessagesEventID = event.listen("net_msg", x)
    end
    
    if self.state == "open" then
        _, msgType, data = event.pull(self.internalReadEventName)
        
        if msgType == "SYN_FIN" then
            return data
        elseif msgType == "WARN" then
            return data
        elseif msgType == "PEER_MSG" then
            return data
        end
    else
        -- Do nothing
    end
end

local function sendPeerMessage(stream, data, newIV, mS, iV, dA, iC)
    return packetBuilder(stream, {[1] = "PEER_MSG", [2] = data, [3] = newIV}, mS, iV, dA, iC)
end

function libnetcrypt:write(data)
    local _          = nil
    local errmsg     = nil
    local msgCorrect = 0
    local msgType    = nil
    local newIV      = nil
    local status     = nil
    local response   = nil
    
    local function y(_, peerAddress, port, data)
        self:incomingNetworkMessagesHandler(peerAddress, port, data)
    end
    
    if not self.sessionHandleIncomingNetworkMessagesEventID and self.state == "open" then
        self.sessionHandleIncomingNetworkMessagesEventID = event.listen("net_msg", y)
    end
    
    if self.state == "open" then
        newIV = datacard.random(16)
        
        status, errmsg = sendPeerMessage(self.stream, data, newIV, self.sessionRecord.masterSecret, self.sessionRecord.iv, self.sessionRecord.digestAlgorithm, self.sessionRecord.isCompressed)
        
        if not status then
            self:close(errmsg)
        end
        
        repeat
            _, msgType, response = event.pull(timeout, self.internalWriteEventName)
            
            if msgType == "" then
                msgCorrect = 1
            elseif msgType == "SYN_FIN" then
                msgCorrect = 1
            elseif msgType == "WARN" then
                if msgType == "RESEND" then
                    status, errmsg = sendPeerMessage(self.stream, data, newIV, self.sessionRecord.masterSecret, self.sessionRecord.iv, self.sessionRecord.digestAlgorithm, self.sessionRecord.isCompressed)
                    if not status then
                        self:close(errmsg)
                    end
                    msgCorrect = 0
                end
            elseif msgType == "OK" then
                if response == "MSG_OK" then
                    self.sessionRecord.iv = newIV
                    msgCorrect = 1
                end
            end
        until(msgCorrect == 1)
    else
        -- Do nothing
    end
end

function libnetcrypt:close(...)
    local _           = nil
    local closeReason = nil
    
    if not ... then
        closeReason = "close_notify"
    else
        closeReason = ...
    end
    
    self.state = "close"
    
    -- Stop listening for network messages, all additional network messages
    -- will be handled below.
    event.cancel(self.sessionHandleIncomingNetworkMessagesEventID)
    
    -- Free up pull events in read and write methods that are potentially
    -- active at the time of calling close().
    event.push(self.internalReadEventName, "SYN_FIN", "Session Terminated")
    event.push(self.internalWriteEventName, "SYN_FIN", "Session Terminated")
    
    _, _ = xpcall(function()
                    ALERT[closeReason](self.stream, self.sessionRecord.masterSecret, self.sessionRecord.iv, self.sessionRecord.digestAlgorithm, self.sessionRecord.isCompressed)
                end,
                function(err)
                    return false
                end)
    
    self.stream:close()
    self.state = nil
    self.stream = nil
    self.sessionHandleIncomingNetworkMessagesEventID = nil
    self.internalReadEventName = nil
    self.internalWriteEventName = nil
    self.sessionRecord = nil
    
    error(string.upper(closeReason))
end

return libnetcrypt
