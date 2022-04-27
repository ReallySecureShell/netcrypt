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
local datacard
local timeout = 60

local libnetcrypt = {}
libnetcrypt.__index = libnetcrypt

-- Create component objects
-------------------------------------------------------------------------------
_, datacard = xpcall(function()
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
    local _      = nil
    local data   = data
    local status = nil
    if not ... then
        -- Perform initial serialization on the data.
        status, data = xpcall(function(originalData)
                                return serial.serialize(originalData)
                            end,
                            function(err)
                                return false
                            end, data)
        if not status then
            data = nil
            return false, "encode_error"
        end
        
        -- Generate a checksum of the message. This is used for crude message
        -- verification before we start sending encrypted data.
        status, data = xpcall(function(dataSerialized)
                                return {["checksum"] = datacard.sha256(dataSerialized), ["data"] = dataSerialized}
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
        status, data = xpcall(function(checksumAndData)
                                return serial.serialize(checksumAndData)
                            end,
                            function(err)
                                return false
                            end, data)
        if not status then
            data = nil
            return false, "encode_error"
        end
        
        -- Write the message to the socket.
        status, _ = xpcall(function(dataFinal)
                            stream:write(dataFinal)
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
        --[=====[
        The message in-full will take the following form:
        
        {
            ["outer_signature"] = "<signature of all contents in ["root"]>", <- String
            ["root"] = {
                ["peer_public_key_checksum"] = "<hash of the peer's public key>", <- String
                ["private"] = { <- All data inside of ["private"] is encrypted. However, in its unencrypted form will be shown. In its encrypted form this is a string.
                    ["inner_signature"] = "<signature of plaintext>", <- String
                    ["message"] = "<plaintext, the original message>" <- Serialized to string
                }
            }
        }
        
        The above demonstrates the sign/encrypt/sign technique described in the
        paper "Defective Sign & Encrypt in S/MIME, PKCS#7, MOSS, PEM, PGP,
        and XML" section 5.2, by Don Davis.
        The paper can be found here:
        https://theworld.com/~dtd/sign_encrypt/sign_encrypt7.html
        --]=====]
        local encryptionMaterial = { ... }
        -- Variables are assigned for code readability.
        local masterSecret    = encryptionMaterial[1]
        local iv              = encryptionMaterial[2]
        local isCompressed    = encryptionMaterial[3]
        local localPrivateKey = encryptionMaterial[4]
        local peerPublicKeyChecksum = encryptionMaterial[5]
        encryptionMaterial    = nil
        
        local PACKET = {
            ["outer_signature"] = "",
            ["root"] = {
                ["peer_public_key_checksum"] = peerPublicKeyChecksum,
                ["private"] = {
                    ["inner_signature"] = "",
                    ["message"] = ""
                }
            }
        }
        
        local function clearPacketBuilderMessageData()
            data                  = nil
            isCompressed          = nil
            iv                    = nil
            localPrivateKey       = nil
            masterSecret          = nil
            PACKET                = nil
            peerPublicKeyChecksum = nil
        end
        
        status, PACKET.root.private.message = xpcall(function(originalData)
                                                        return serial.serialize(originalData)
                                                    end,
                                                    function(err)
                                                        return false
                                                    end, data)
        if not status then
            clearPacketBuilderMessageData()
            return false, "encode_error"
        end
        
        status, PACKET.root.private.inner_signature = xpcall(function(rootPrivateMessageSerialized)
                                                                return datacard.ecdsa(rootPrivateMessageSerialized, localPrivateKey)
                                                            end,
                                                            function(err)
                                                                return false
                                                            end, PACKET.root.private.message)
        if not status then
            clearPacketBuilderMessageData()
            return false, "internal_error"
        end
        
        status, PACKET.root.private = xpcall(function(rootPrivate)
                                                return serial.serialize(rootPrivate)
                                            end,
                                            function(err)
                                                return false
                                            end, PACKET.root.private)
        if not status then
            clearPacketBuilderMessageData()
            return false, "encode_error"
        end
        
        status, PACKET.root.private = xpcall(function(rootPrivateSerialized)
                                                return datacard.encrypt(rootPrivateSerialized, masterSecret, iv)
                                            end,
                                            function(err)
                                                return false
                                            end, PACKET.root.private)
        if not status then
            clearPacketBuilderMessageData()
            return false, "encrypt_error"
        end
        
        status, PACKET.root = xpcall(function(root)
                                        return serial.serialize(root)
                                    end,
                                    function(err)
                                        return false
                                    end, PACKET.root)
        if not status then
            clearPacketBuilderMessageData()
            return false, "encode_error"
        end
        
        status, PACKET.outer_signature = xpcall(function(rootSerialized)
                                                return datacard.ecdsa(rootSerialized, localPrivateKey)
                                            end,
                                            function(err)
                                                return false
                                            end, PACKET.root)
        if not status then
            clearPacketBuilderMessageData()
            return false, "internal_error"
        end
        
        status, PACKET = xpcall(function(packet)
                                return serial.serialize(packet)
                            end,
                            function(err)
                                return false
                            end, PACKET)
        if not status then
            clearPacketBuilderMessageData()
            return false, "encode_error"
        end
        
        if isCompressed == true then
            status, PACKET = xpcall(function(packetSerialized)
                                    return datacard.deflate(packetSerialized)
                                end,
                                function(err)
                                    return false
                                end, PACKET)
            if not status then
                clearPacketBuilderMessageData()
                return false, "compression_error"
            end
        end
        
        status, _ = xpcall(function(packetFinal)
                            stream:write(packetFinal)
                        end,
                        function(err)
                            return false
                        end, PACKET)
        if not status then
            clearPacketBuilderMessageData()
            return false, "transmission_failure"
        end
        
        clearPacketBuilderMessageData()
        return true, ""
    end
end

-- Perform operations to recover the original network message.
local function packetDeconstructor(data, ...)
    local _      = nil
    local data   = data
    local status = nil
    if not ... then
        -- Unserialize the initial message.
        status, data = xpcall(function(serializedData)
                                return serial.unserialize(serializedData)
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
        status, _ = xpcall(function(checksum, serializedData)
                            if datacard.sha256(serializedData) ~= checksum then
                                error()
                            else
                                return true
                            end
                        end,
                        function(err)
                            return false
                        end, data.checksum, data.data)
        if not status then
            data = nil
            return false, "bad_checksum", ""
        end
        
        -- Unserialize the data portion of the message.
        status, data.data = xpcall(function(serializedData)
                                    return serial.unserialize(serializedData)
                                end,
                                function(err)
                                    return false
                                end, data.data)
        if not status then
            data = nil
            return false, "decode_error", ""
        end
        
        return true, "", data.data
    else
        local encryptionMaterial = { ... }
        local masterSecret  = encryptionMaterial[1]
        local iv            = encryptionMaterial[2]
        local isCompressed  = encryptionMaterial[3]
        local peerPublicKey = encryptionMaterial[4]
        local localPublicKeyChecksum = encryptionMaterial[5]
        encryptionMaterial  = nil
        
        local function clearPacketDeconstructorMessageData()
            isCompressed           = nil
            iv                     = nil
            localPublicKeyChecksum = nil
            masterSecret           = nil
            peerPublicKey          = nil
        end
        
        if isCompressed == true then
            status, data = xpcall(function(compressedData)
                                    return datacard.inflate(compressedData)
                                end,
                                function(err)
                                    return false
                                end, data)
            if not status then
                data = nil
                clearPacketDeconstructorMessageData()
                return false, "decompression_error", ""
            end
        end
        
        status, data = xpcall(function(serializedData)
                                return serial.unserialize(serializedData)
                            end,
                            function(err)
                                return false
                            end, data)
        if not status then
            data = nil
            clearPacketDeconstructorMessageData()
            return false, "decode_error", ""
        end
        
        status, _ = xpcall(function(rootSerialized, outerSignature)
                            if datacard.ecdsa(rootSerialized, peerPublicKey, outerSignature) == false then
                                error()
                            else
                                return true
                            end
                        end,
                        function(err)
                            return false
                        end, data.root, data.outer_signature)
        if not status then
            data = nil
            clearPacketDeconstructorMessageData()
            return false, "bad_mac", ""
        end
        
        status, data.root = xpcall(function(rootSerialized)
                                    return serial.unserialize(rootSerialized)
                                end,
                                function(err)
                                    return false
                                end, data.root)
        if not status then
            data = nil
            clearPacketDeconstructorMessageData()
            return false, "decode_error", ""
        end
        
        status, _ = xpcall(function(peerPublicKeyChecksum)
                            if localPublicKeyChecksum ~= peerPublicKeyChecksum then
                                error()
                            else
                                return true
                            end
                        end,
                        function(err)
                            return false
                        end, data.root.peer_public_key_checksum)
        if not status then
            data = nil
            clearPacketDeconstructorMessageData()
            return false, "bad_checksum", ""
        end
        
        status, data.root.private = xpcall(function(rootPrivateEncrypted)
                                            return datacard.decrypt(rootPrivateEncrypted, masterSecret, iv)
                                        end,
                                        function(err)
                                            return false
                                        end, data.root.private)
        if not status then
            data = nil
            clearPacketDeconstructorMessageData()
            return false, "decrypt_error", ""
        end
        
        status, data.root.private = xpcall(function(rootPrivateSerialized)
                                            return serial.unserialize(rootPrivateSerialized)
                                        end,
                                        function(err)
                                            return false
                                        end, data.root.private)
        if not status then
            data = nil
            clearPacketDeconstructorMessageData()
            return false, "decode_error", ""
        end
        
        status, _ = xpcall(function(rootPrivateMessageSerialized, innerSignature)
                            if datacard.ecdsa(rootPrivateMessageSerialized, peerPublicKey, innerSignature) == false then
                                error()
                            else
                                return true
                            end
                        end,
                        function(err)
                            return false
                        end, data.root.private.message, data.root.private.inner_signature)
        if not status then
            data = nil
            clearPacketDeconstructorMessageData()
            return false, "bad_mac", ""
        end
        
        status, data.root.private.message = xpcall(function(rootPrivateMessageSerialized)
                                                    return serial.unserialize(rootPrivateMessageSerialized)
                                                end,
                                                function(err)
                                                    return false
                                                end, data.root.private.message)
        if not status then
            data = nil
            clearPacketDeconstructorMessageData()
            return false, "decode_error", ""
        end
        
        clearPacketDeconstructorMessageData()
        return true, "", data.root.private.message
    end
end

local ALERT = {
    ["bad_certificate"]      = function(stream, ...) _, _ = packetBuilder(stream, {["msg_type"] = "FATAL", ["msg"] = "BAD_CERTIFICATE"}, ...) end, -- A certificate was corrupt in some way.
    ["bad_checksum"]         = function(stream, ...) _, _ = packetBuilder(stream, {["msg_type"] = "FATAL", ["msg"] = "BAD_CHECKSUM"}, ...) end, -- When comparing the checksums of the sent and received message, the checksums did not match.
    ["bad_mac"]              = function(stream, ...) _, _ = packetBuilder(stream, {["msg_type"] = "FATAL", ["msg"] = "BAD_MAC"}, ...) end, -- The signature of the message does not match the contents of the actual received message. Someone may be trying to modify the contents of the message, or the message may have gotten corrupted in some way. During normal communication, this alert is handled specially, in that it will not cause the stream to close. This prevents someone from intentionally modifying a message to cause the stream to close, as that would create a denial of service vulnerability.
    ["bad_record"]           = function(stream, ...) _, _ = packetBuilder(stream, {["msg_type"] = "FATAL", ["msg"] = "BAD_RECORD"}, ...) end, -- A message had an different hash value than the expected hash value.
    ["close_notify"]         = function(stream, ...) _, _ = packetBuilder(stream, {["msg_type"] = "FATAL", ["msg"] = "CLOSE_NOTIFY"}, ...) end, -- Not an error, but the stream must close immediately.
    ["compression_error"]    = function(stream, ...) _, _ = packetBuilder(stream, {["msg_type"] = "FATAL", ["msg"] = "COMPRESSION_ERROR"}, ...) end, -- The data was unable to be compressed due to an error.
    ["decode_error"]         = function(stream, ...) _, _ = packetBuilder(stream, {["msg_type"] = "FATAL", ["msg"] = "DECODE_ERROR"}, ...) end, -- When deserialization fails.
    ["decompression_error"]  = function(stream, ...) _, _ = packetBuilder(stream, {["msg_type"] = "FATAL", ["msg"] = "DECOMPRESSION_ERROR"}, ...) end, -- A message was unable to be decompressed.
    ["decrypt_error"]        = function(stream, ...) _, _ = packetBuilder(stream, {["msg_type"] = "FATAL", ["msg"] = "DECRYPT_ERROR"}, ...) end, -- The message was unable to be decrypted.
    ["encode_error"]         = function(stream, ...) _, _ = packetBuilder(stream, {["msg_type"] = "FATAL", ["msg"] = "ENCODE_ERROR"}, ...) end, -- An error occurred while attempting to serialize the data.
    ["encrypt_error"]        = function(stream, ...) _, _ = packetBuilder(stream, {["msg_type"] = "FATAL", ["msg"] = "ENCRYPT_ERROR"}, ...) end, -- Encryption of data failed.
    ["handshake_failure"]    = function(stream, ...) _, _ = packetBuilder(stream, {["msg_type"] = "FATAL", ["msg"] = "HANDSHAKE_FAILURE"}, ...) end, -- An error of some kind relating to the handshake occurred.
    ["internal_error"]       = function(stream, ...) _, _ = packetBuilder(stream, {["msg_type"] = "FATAL", ["msg"] = "INTERNAL_ERROR"}, ...) end, -- An error unrelated to the protocol has occurred.
    ["msg_ok"]               = function(stream, ...) _, _ = packetBuilder(stream, {["msg_type"] = "OK",    ["msg"] = "MSG_OK"}, ...) end, -- The peer sent a message that did not result in any error(s) occurring. The message content itself may be a fatal message, however the message was able to be deconstructed successfully.
    ["resend"]               = function(stream, ...) _, _ = packetBuilder(stream, {["msg_type"] = "WARN",  ["msg"] = "RESEND"}, ...) end, -- The peer sent a message that had a bad_checksum, as a result, the peer is asked to resend the message.
    ["transmission_failure"] = function(stream, ...) _, _ = packetBuilder(stream, {["msg_type"] = "FATAL", ["msg"] = "TRANSMISSION_FAILURE"}, ...) end, -- An error occurred while attempting to send the message.
    ["unexpected_message"]   = function(stream, ...) _, _ = packetBuilder(stream, {["msg_type"] = "FATAL", ["msg"] = "UNEXPECTED_MESSAGE"}, ...) end, -- The peer sent a message that does not conform to the standard formatting of messages in this protocol.
}
-------------------------------------------------------------------------------

function libnetcrypt.open(peerAddress, port, ...)
    checkArg(1, peerAddress, "string")
    checkArg(2, port, "number")
    
    -- Is used through the rest of the session.
    local internalReadEventName  = nil
    local internalWriteEventName = nil
    local isCompressed           = nil
    local iv                     = nil
    local keySize                = nil
    local localPrivateKey        = nil
    local localPublicKey         = nil
    local localPublicKeyChecksum = nil
    local masterSecret           = nil
    local peerPublicKey          = nil
    local peerPublicKeyChecksum  = nil
    local stream                 = nil
    -- Is only used within the handshake.
    local clientFinishedTable    = nil
    local clientSupportedCiphers = nil
    local digestAlgorithm        = nil
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
        isCompressed           = nil
        iv                     = nil
        keySize                = nil
        localPrivateKey        = nil
        localPublicKey         = nil
        localPublicKeyChecksum = nil
        masterSecret           = nil
        peerPublicKey          = nil
        peerPublicKeyChecksum  = nil
        stream                 = nil
        -- Is only used within the handshake.
        clientFinishedTable    = nil
        clientSupportedCiphers = nil
        digestAlgorithm        = nil
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
    status, errmsg = packetBuilder(stream, {["msg_type"] = "CLIENT_HELLO", ["msg"] = ""})
    
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
            status, errmsg, data = packetDeconstructor(data, masterSecret, iv, isCompressed, peerPublicKey, localPublicKeyChecksum)
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
        if data["msg_type"] == "FATAL" then
            clearHandshakeData(stream)
            error(data["msg"])
        else
            -- The first item in the 'data' table indicates the type of handshake
            -- message. If the received handshake message is equal to the string in
            -- the last key inside of the
            -- 'orderOfExpectedHandshakeMessagesFromServer' table, we know that is
            -- the current step of the handshake, and we need to process that data.
            if data["msg_type"] == orderOfExpectedHandshakeMessagesFromServer[#orderOfExpectedHandshakeMessagesFromServer] then
                if data["msg_type"] == "SERVER_HELLO" then
                    -- Send client 'chosen' ciphers. At this time, there is no plans to have a cipher negotiation sub-protocol. YOU MUST know the ciphersuite of the server before connecting.
                    -- However, the default ciphersuite for the client/server is the same, which is balanced for security and speed.
                    status, errmsg = packetBuilder(stream, {["msg_type"] = "CLIENT_SELECTED_CIPHERS", ["msg"] = clientSupportedCiphers})
                    if not status then
                        ALERT[errmsg](stream)
                        clearHandshakeData(stream)
                        error(string.upper(errmsg))
                    end
                    table.remove(orderOfExpectedHandshakeMessagesFromServer, #orderOfExpectedHandshakeMessagesFromServer)
                elseif data["msg_type"] == "SERVER_SELECTED_CIPHERS" then
                    -- Set the chosen ciphersuite.
                    keySize         = data["msg"].keySize
                    digestAlgorithm = data["msg"].digestAlgorithm
                    isCompressed    = data["msg"].isCompressed
                    table.remove(orderOfExpectedHandshakeMessagesFromServer, #orderOfExpectedHandshakeMessagesFromServer)
                elseif data["msg_type"] == "SERVER_KEY_SHARE" then
                    -- Rebuild the public key object from the server.
                    status, peerPublicKey = xpcall(function()
                                                    return datacard.deserializeKey(data["msg"].serverPublicKey, "ec-public")
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
                    
                    -- Storing the hashed version of the key allows us to
                    -- save on computational power later on, such as when
                    -- signing and verifying messages.
                    if digestAlgorithm == "sha" then
                        peerPublicKeyChecksum = datacard.sha256(peerPublicKey.serialize())
                    elseif digestAlgorithm == "md5" then
                        peerPublicKeyChecksum = datacard.md5(peerPublicKey.serialize())
                    end
                    
                    -- The server-generated initialization vector.
                    iv = data["msg"].iv
                    
                    -- Generate asymmetric keypair, then send the public key to the server.
                    localPublicKey, localPrivateKey = datacard.generateKeyPair(keySize)
                    
                    if digestAlgorithm == "sha" then
                        localPublicKeyChecksum = datacard.sha256(localPublicKey.serialize())
                    elseif digestAlgorithm == "md5" then
                        localPublicKeyChecksum = datacard.md5(localPublicKey.serialize())
                    end
                    
                    -- Generate the Diffie-Hellman shared key. It is always represented as a
                    -- md5 hash, regardless of the chosen ciphersuite.
                    masterSecret = datacard.md5(datacard.ecdh(localPrivateKey, peerPublicKey))
                    
                    -- Send client public key to server.
                    status, errmsg = packetBuilder(stream, {["msg_type"] = "CLIENT_KEY_SHARE", ["msg"] = {["clientPublicKey"] = localPublicKey.serialize()}})
                    
                    if not status then
                        ALERT[errmsg](stream)
                        clearHandshakeData(stream)
                        error(string.upper(errmsg))
                    end
                    
                    -- Send the 'CLIENT_FINISHED' message. All information that the client
                    -- sent to the server is repeated over an encrypted connection.
                    clientFinishedTable = {
                    ["msg_type"] = "CLIENT_FINISHED",
                    ["msg"] = {
                                ["CLIENT_SELECTED_CIPHERS"] = clientSupportedCiphers,
                                ["CLIENT_KEY_SHARE"] = {["clientPublicKey"] = localPublicKey.serialize()},
                              }
                    }
                    status, errmsg = packetBuilder(stream, clientFinishedTable, masterSecret, iv, isCompressed, localPrivateKey, peerPublicKeyChecksum)
                    
                    if not status then
                        ALERT[errmsg](stream)
                        clearHandshakeData(stream)
                        error(string.upper(errmsg))
                    end
                    table.remove(orderOfExpectedHandshakeMessagesFromServer, #orderOfExpectedHandshakeMessagesFromServer)
                elseif data["msg_type"] == "SERVER_FINISHED" then
                    status, _ = xpcall(function()
                                        if data["msg"].SERVER_SELECTED_CIPHERS.keySize ~= keySize then
                                            error()
                                        elseif data["msg"].SERVER_SELECTED_CIPHERS.digestAlgorithm ~= digestAlgorithm then
                                            error()
                                        elseif data["msg"].SERVER_SELECTED_CIPHERS.isCompressed ~= isCompressed then
                                            error()
                                        elseif data["msg"].SERVER_KEY_SHARE.serverPublicKey ~= peerPublicKey.serialize() then
                                            error()
                                        elseif data["msg"].SERVER_KEY_SHARE.iv ~= iv then
                                            error()
                                        else
                                            return true
                                        end
                                    end,
                                    function(err)
                                        return false
                                    end)
                    if not status then
                        ALERT["bad_record"](stream, masterSecret, iv, isCompressed, localPrivateKey, peerPublicKeyChecksum)
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
    status, errmsg, data = packetDeconstructor(data, masterSecret, iv, isCompressed, peerPublicKey, localPublicKeyChecksum)
    
    if data == "" then
        -- Do nothing
    elseif data["msg_type"] == "FATAL" then
        clearHandshakeData(stream)
        error(data["msg"])
    end
    
    -- Clear variables that are only used during the handshake.
    clientFinishedTable    = nil
    clientSupportedCiphers = nil
    data                   = nil
    digestAlgorithm        = nil
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
            isCompressed    = isCompressed,
            iv              = iv,
            keySize         = keySize,
            localPrivateKey = localPrivateKey,
            localPublicKey  = localPublicKey,
            localPublicKeyChecksum = localPublicKeyChecksum,
            masterSecret    = masterSecret,
            peerAddress     = peerAddress,
            peerPublicKey   = peerPublicKey,
            peerPublicKeyChecksum = peerPublicKeyChecksum,
            port            = port,
        };
    }, libnetcrypt)
end

-- Debugging
-- local foo = libnetcrypt.open("AE-PLC", 9999, {[1] = 256}, {[1] = "sha"}, {[1] = true})

function libnetcrypt.listen(port, ...)
    checkArg(1, port, "number")
    
    -- Is used through the rest of the session.
    local internalReadEventName  = nil
    local internalWriteEventName = nil
    local isCompressed           = nil
    local iv                     = nil
    local keySize                = nil
    local localPrivateKey        = nil
    local localPublicKey         = nil
    local localPublicKeyChecksum = nil
    local masterSecret           = nil
    local peerAddress            = nil
    local peerPublicKey          = nil
    local peerPublicKeyChecksum  = nil
    local stream                 = nil
    -- Is only used within the handshake.
    local digestAlgorithm        = nil
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
        isCompressed           = nil
        iv                     = nil
        keySize                = nil
        localPrivateKey        = nil
        localPublicKey         = nil
        localPublicKeyChecksum = nil
        masterSecret           = nil
        peerAddress            = nil
        peerPublicKey          = nil
        peerPublicKeyChecksum  = nil
        stream                 = nil
        -- Is only used within the handshake.
        digestAlgorithm        = nil
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
            status, errmsg, data = packetDeconstructor(data, masterSecret, iv, isCompressed, peerPublicKey, localPublicKeyChecksum)
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
        
        if data["msg_type"] == "FATAL" then
            clearHandshakeData(stream)
            error(data["msg"])
        else
            if data["msg_type"] == orderOfExpectedHandshakeMessagesFromClient[#orderOfExpectedHandshakeMessagesFromClient] then
                if data["msg_type"] == "CLIENT_HELLO" then
                    -- Send SERVER_HELLO message
                    status, errmsg = packetBuilder(stream, {["msg_type"] = "SERVER_HELLO", ["msg"] = ""})
                    if not status then
                        ALERT[errmsg](stream)
                        clearHandshakeData(stream)
                        error(string.upper(errmsg))
                    end
                    table.remove(orderOfExpectedHandshakeMessagesFromClient, #orderOfExpectedHandshakeMessagesFromClient)
                elseif data["msg_type"] == "CLIENT_SELECTED_CIPHERS" then
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
                    
                    initialClientSelectedCiphers = data["msg"]
                    
                    local breakLoop = 0
                    for sPriority, sValue in ipairs(serverSupportedCiphers["keySizes"]) do
                        for cPriority, cValue in ipairs(data["msg"]["keySizes"]) do
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
                        for cPriority, cValue in ipairs(data["msg"]["digestAlgorithms"]) do
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
                        for cPriority, cValue in ipairs(data["msg"]["useCompression"]) do
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
                    
                    status, errmsg = packetBuilder(stream, {["msg_type"] = "SERVER_SELECTED_CIPHERS", ["msg"] = {["keySize"] = keySize, ["digestAlgorithm"] = digestAlgorithm, ["isCompressed"] = isCompressed}})
                    
                    if not status then
                        ALERT[errmsg](stream)
                        clearHandshakeData(stream)
                        error(string.upper(errmsg))
                    end
                    
                    -- SERVER_KEY_SHARE --
                    
                    iv = datacard.random(16)
                    
                    localPublicKey, localPrivateKey = datacard.generateKeyPair(keySize)
                    
                    if digestAlgorithm == "sha" then
                        localPublicKeyChecksum = datacard.sha256(localPublicKey.serialize())
                    elseif digestAlgorithm == "md5" then
                        localPublicKeyChecksum = datacard.md5(localPublicKey.serialize())
                    end
                    
                    -- Send the server public key and IV to the client.
                    status, errmsg = packetBuilder(stream, {["msg_type"] = "SERVER_KEY_SHARE", ["msg"] = {["serverPublicKey"] = localPublicKey.serialize(), ["iv"] = iv}})
                    
                    if not status then
                        ALERT[errmsg](stream)
                        clearHandshakeData(stream)
                        error(string.upper(errmsg))
                    end
                    table.remove(orderOfExpectedHandshakeMessagesFromClient, #orderOfExpectedHandshakeMessagesFromClient)
                elseif data["msg_type"] == "CLIENT_KEY_SHARE" then
                    -- Rebuild the public key object from the server.
                    status, peerPublicKey = xpcall(function()
                                                    return datacard.deserializeKey(data["msg"].clientPublicKey, "ec-public")
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
                    
                    if digestAlgorithm == "sha" then
                        peerPublicKeyChecksum = datacard.sha256(peerPublicKey.serialize())
                    elseif digestAlgorithm == "md5" then
                        peerPublicKeyChecksum = datacard.md5(peerPublicKey.serialize())
                    end
                    
                    masterSecret = datacard.md5(datacard.ecdh(localPrivateKey, peerPublicKey))
                    table.remove(orderOfExpectedHandshakeMessagesFromClient, #orderOfExpectedHandshakeMessagesFromClient)
                elseif data["msg_type"] == "CLIENT_FINISHED" then
                    status, _ = xpcall(function()
                                        if serial.serialize(data["msg"].CLIENT_SELECTED_CIPHERS) ~= serial.serialize(initialClientSelectedCiphers) then
                                            error()
                                        elseif data["msg"].CLIENT_KEY_SHARE.clientPublicKey ~= peerPublicKey.serialize() then
                                            error()
                                        else
                                            return true
                                        end
                                    end,
                                    function(err)
                                        return false
                                    end)
                    if not status then
                        ALERT["bad_record"](stream, masterSecret, iv, isCompressed, localPrivateKey, peerPublicKeyChecksum)
                        clearHandshakeData(stream)
                        error("BAD_RECORD")
                    end
                    
                    -- SERVER_FINISHED --
                    
                    serverFinishedTable = {
                    ["msg_type"] = "SERVER_FINISHED",
                    ["msg"] = {
                                ["SERVER_SELECTED_CIPHERS"] = {["keySize"] = keySize, ["digestAlgorithm"] = digestAlgorithm, ["isCompressed"] = isCompressed},
                                ["SERVER_KEY_SHARE"] = {["serverPublicKey"] = localPublicKey.serialize(), ["iv"] = iv},
                              }
                    }
                    status, errmsg = packetBuilder(stream, serverFinishedTable, masterSecret, iv, isCompressed, localPrivateKey, peerPublicKeyChecksum)
                    
                    if not status then
                        ALERT[errmsg](stream, masterSecret, iv, isCompressed, localPrivateKey, peerPublicKeyChecksum)
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
    
    status, errmsg, data = packetDeconstructor(data, masterSecret, iv, isCompressed, peerPublicKey, localPublicKeyChecksum)
    
    if data == "" then
        -- Do nothing
    elseif data["msg_type"] == "FATAL" then
        clearHandshakeData(stream)
        error(data["msg"])
    end
    
    -- Clear variables that are only used during the handshake.
    data                   = nil
    digestAlgorithm        = nil
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
            isCompressed    = isCompressed,
            iv              = iv,
            keySize         = keySize,
            localPrivateKey = localPrivateKey,
            localPublicKey  = localPublicKey,
            localPublicKeyChecksum = localPublicKeyChecksum,
            masterSecret    = masterSecret,
            peerAddress     = peerAddress,
            peerPublicKey   = peerPublicKey,
            peerPublicKeyChecksum = peerPublicKeyChecksum,
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
        status, errmsg, data = packetDeconstructor(data, self.sessionRecord.masterSecret, self.sessionRecord.iv, self.sessionRecord.isCompressed, self.sessionRecord.peerPublicKey, self.sessionRecord.localPublicKeyChecksum)
        if not status then
            -- The peer sent a message whose hash did not match the provided hash within the message.
            -- Instead of telling the peer they sent a message with a bad checksum, ask the peer to
            -- resend the message.
            if errmsg == "bad_checksum" then
                ALERT["resend"](self.stream, self.sessionRecord.masterSecret, self.sessionRecord.iv, self.sessionRecord.isCompressed, self.sessionRecord.localPrivateKey, self.sessionRecord.peerPublicKeyChecksum)
                event.push(self.internalReadEventName, "WARN", string.upper(errmsg))
            else
                self:close(errmsg)
            end
        else
            if data["msg_type"] == "FATAL" then
                if data["msg"] == "BAD_MAC" then
                    -- Do nothing
                else
                    self:close(data["msg"])
                end
            elseif data["msg_type"] == "WARN" then
                if data["msg"] == "RESEND" then
                    event.push(self.internalWriteEventName, "WARN", "RESEND")
                end
            elseif data["msg_type"] == "PEER_MSG" then
                ALERT["msg_ok"](self.stream, self.sessionRecord.masterSecret, self.sessionRecord.iv, self.sessionRecord.isCompressed, self.sessionRecord.localPrivateKey, self.sessionRecord.peerPublicKeyChecksum)
                self.sessionRecord.iv = data["new_iv"]
                event.push(self.internalReadEventName, "PEER_MSG", data["msg"])
            elseif data["msg_type"] == "OK" then
                if data["msg"] == "MSG_OK" then
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

local function sendPeerMessage(stream, data, newIV, mS, iV, iC, lPvtK, pPubKChk)
    return packetBuilder(stream, {["msg_type"] = "PEER_MSG", ["msg"] = data, ["new_iv"] = newIV}, mS, iV, iC, lPvtK, pPubKChk)
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
        
        status, errmsg = sendPeerMessage(self.stream, data, newIV, self.sessionRecord.masterSecret, self.sessionRecord.iv, self.sessionRecord.isCompressed, self.sessionRecord.localPrivateKey, self.sessionRecord.peerPublicKeyChecksum)
        
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
                    status, errmsg = sendPeerMessage(self.stream, data, newIV, self.sessionRecord.masterSecret, self.sessionRecord.iv, self.sessionRecord.isCompressed, self.sessionRecord.localPrivateKey, self.sessionRecord.peerPublicKeyChecksum)
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
                    ALERT[closeReason](self.stream, self.sessionRecord.masterSecret, self.sessionRecord.iv, self.sessionRecord.isCompressed, self.sessionRecord.localPrivateKey, self.sessionRecord.peerPublicKeyChecksum)
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
