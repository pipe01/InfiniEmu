local pt = pinetime.new { firmware = "/home/pipe/git/InfiniTime/build/src/pinetime-app-1.16.0.out" }

local adv_access_address <const> = buffer.new({ 0x8e, 0x89, 0xbe, 0xd6 }):reverse()

local our_address <const> = buffer.new({ 0x0a, 0x1f, 0x63, 0x39, 0xb0, 0x47 }):reverse()

local our_access_address <const> = buffer.new({ 0xaa, 0xbb, 0xcc, 0xdd }):reverse()

local sent_req = false

local Packet = require("lua/packet")

local ADV_IND <const> = 0x00
local SCAN_REQ <const> = 0x03
local SCAN_RSP <const> = 0x04
local CONNECT_IND <const> = 0x05

local LL_PERIPHERAL_FEATURE_REQ <const> = 0x0E
local LL_FEATURE_RSP <const> = 0x09
local LL_LENGTH_REQ <const> = 0x14
local LL_LENGTH_RSP <const> = 0x15

local L2CAP_CHANNEL_ATT <const> = 0x04

local fakeCRC <const> = buffer.new({ 0xFF, 0xFF, 0xFF })

local transmitSeqNum = 0
local nextExpectedSeqNum = 0

local last_packet_sent_time = 0
local packet_queue = {}

local packet_log_file = assert(io.open("packets.log", "w"))
local comms_log_file = assert(io.open("comms.log", "w"))

local LEUncodedPacket <const> = Packet.define("LEUncodedPacket")
    :bytes("access_address", 4)
    :bytes_rest("pdu")
    :build()

local AdvertisingChannelPDU <const> = Packet.define("AdvertisingChannelPDU")
    :bitfield("header", 2, {
        { "PDU_Type", 4 },
        { "RFU", 1 },
        { "ChSel", 1 },
        { "TxAdd", 1 },
        { "RxAdd", 1 },
        { "Length", 8 },
    })
    :bytes_rest("payload")
    :build()

local AdvertisingADV_IND <const> = Packet.define("ADV_IND")
    :bytes("AdvA", 6)
    :bytes_rest("AdvData")
    :build()

local AdvertisingSCAN_REQ <const> = Packet.define("SCAN_REQ")
    :bytes("ScanA", 6)
    :bytes("AdvA", 6)
    :build()

local AdvertisingSCAN_RSP <const> = Packet.define("SCAN_RSP")
    :bytes("AdvA", 6)
    :bytes_rest("ScanRspData")
    :build()

local AdvertisingCONNECT_IND <const> = Packet.define("CONNECT_IND")
    :bytes("InitA", 6)
    :bytes("AdvA", 6)
    :bytes("AA", 4)
    :bytes("CRCInit", 3)
    :u8("WinSize")
    :u16("WinOffset")
    :u16("Interval")
    :u16("Latency")
    :u16("Timeout")
    :bytes("ChM", 5)
    :bitfield("Hop_SCA", 1, {
        { "Hop", 5 },
        { "SCA", 3 },
    })
    :build()

local DataPhysicalChannelPDU <const> = Packet.define("DataPhysicalChannelPDU")
    :bitfield("header", 2, {
        { "LLID", 2 },
        { "NESN", 1 },
        { "SN", 1 },
        { "MD", 1 },
        { "CP", 1 },
        { "RFU", 2 },
        { "Length", 8 },
    })
    :bytes_rest("payload")
    :build()

local AttributePDU <const> = Packet.define("AttributePDU")
    :bitfield("Header", 1, {
        { "Method", 6 },
        { "Command", 1 },
        { "Auth", 1 },
    })
    :bytes_rest("Parameters")
    :build()

local AttributeATT_FIND_BY_TYPE_VALUE_REQ <const> = Packet.define("ATT_FIND_BY_TYPE_VALUE_REQ")
    :u16("StartingHandle")
    :u16("EndingHandle")
    :u16("AttributeType")
    :bytes_rest("AttributeValue")
    :build()

local AttributeATT_ERROR_RSP <const> = Packet.define("ATT_ERROR_RSP")
    :u8("RequestOpcode")
    :u16("AttributeHandle")
    :u8("ErrorCode")
    :build()

local AttributeATT_HANDLE_VALUE_NTF <const> = Packet.define("ATT_HANDLE_VALUE_NTF")
    :u16("AttributeHandle")
    :bytes_rest("AttributeValue")
    :build()

function log_packet(packet, level)
    packet_log_file:write(string.format("[%f] %d: %s", pt:rantime(), level, packet))
    packet_log_file:write("\n\n")
end

function debug_log(...)
    -- print(...)
end

function send(packet)
    local with_crc = packet .. fakeCRC

    comms_log_file:write("-> " .. #with_crc .. " bytes: " .. tostring(with_crc) .. "\n")
    pt:sendradio(with_crc)
    last_packet_sent_time = pt:rantime()
end

function queue_packet(packet)
    table.insert(packet_queue, packet)
end

function dequeue_packet()
    return table.remove(packet_queue, 1)
end

function queue_le_packet(payload)
    queue_packet(LEUncodedPacket.encode {
        access_address = our_access_address,
        pdu = payload,
    })
end

function queue_ll_control_pdu(opcode, params)
    local payload = buffer.new({ opcode }) .. params
    queue_le_packet(DataPhysicalChannelPDU.encode {
        header = {
            LLID = 3,
            NESN = nextExpectedSeqNum,
            SN = transmitSeqNum,
            Length = #payload,
        },
        payload = payload
    })
end

function queue_ll_data_pdu(payload)
    queue_le_packet(DataPhysicalChannelPDU.encode {
        header = {
            LLID = 2, -- LLID is 2 for first L2CAP fragment and 1 for others
            NESN = nextExpectedSeqNum,
            SN = transmitSeqNum,
            Length = #payload,
        },
        payload = payload
    })
end

function queue_advertising_packet(pdu_type, payload)
    queue_packet(LEUncodedPacket.encode {
        access_address = adv_access_address,
        pdu = AdvertisingChannelPDU.encode {
            header = {
                PDU_Type = pdu_type,
                Length = #payload,
            },
            payload = payload
        },
    })
end

function queue_l2cap_packet(channel, payload)
    local pdu_length = #payload
    local l2cap_payload = buffer.new {
        pdu_length & 0xFF,
        (pdu_length >> 8) & 0xFF,
        channel & 0xFF,
        (channel >> 8) & 0xFF,
    } .. payload

    queue_ll_data_pdu(l2cap_payload)
end

function queue_attribute_packet(opcode, payload)
    queue_l2cap_packet(L2CAP_CHANNEL_ATT, buffer.new({ opcode }) .. payload)
end

function le16(value)
    return buffer.new({ value & 0xFF, (value >> 8) & 0xFF })
end

function fromle16(buffer, start)
    return buffer[start] | (buffer[start + 1] << 8)
end

-- Vol 6 Part B Section 2.4
function handle_data_physical_channel(data)
    local packet = DataPhysicalChannelPDU.decode(data)
    if packet.header.Length > 0 then log_packet(packet, 1) end

    assert(#packet.payload == packet.header.Length)

    local llid = packet.header.LLID
    local nesn = packet.header.NESN
    local sn = packet.header.SN

    if sn == nextExpectedSeqNum then
        -- Good packet, increment
        nextExpectedSeqNum = 1 - nextExpectedSeqNum
        debug_log("[*] Good packet received")
    else
        debug_log("[*] Ignoring resent packet")
        return
    end

    if nesn == transmitSeqNum then
        debug_log("[*] Last packet not acknowledged")
    else
        debug_log("[*] Last packet acknowledged")

        -- Last packet was received, increment seqnum
        transmitSeqNum = 1 - transmitSeqNum
    end

    local is_data = llid == 1 or llid == 2
    if is_data then
        debug_log("LL Data PDU")
    else
        debug_log("LL Control PDU")
    end

    if is_data then
        if #packet.payload > 0 then
            handle_l2cap(packet.payload)
        else
            debug_log("Ignoring empty packet")
        end
    else
        local opcode = packet.payload[0]
        local params = packet.payload:slice(1)

        handle_ll_control(opcode, params)
    end
end

function handle_advertising_channel(pdu)
    local adv_packet = AdvertisingChannelPDU.decode(pdu)
    log_packet(adv_packet, 1)

    if adv_packet.header.PDU_Type == ADV_IND then
        local adv_ind = AdvertisingADV_IND.decode(adv_packet.payload)
        log_packet(adv_ind, 2)

        if not sent_req then
            sent_req = true

            queue_advertising_packet(SCAN_REQ, AdvertisingSCAN_REQ.encode {
                ScanA = our_address,
                AdvA = adv_ind.AdvA
            })
        end
    elseif adv_packet.header.PDU_Type == SCAN_RSP then
        local scan_rsp = AdvertisingSCAN_RSP.decode(adv_packet.payload)
        log_packet(scan_rsp, 2)

        queue_advertising_packet(CONNECT_IND, AdvertisingCONNECT_IND.encode {
            InitA = our_address,
            AdvA = scan_rsp.AdvA,
            AA = our_access_address,
            CRCInit = buffer.new({ 0xBB, 0xBB, 0xBB }),
            WinSize = 1800,
            WinOffset = 0,
            Interval = 200,
            Latency = 1,
            Timeout = 1600,
            ChM = buffer.new({ 0xCC, 0xCC, 0xCC, 0xCC, 0xCC }),
            Hop_SCA = {
                Hop = 7,
                SCA = 0,
            }
        })

        connected = true
    else
        assert(false, "Unknown advertising PDU type " .. tostring(adv_packet.header.PDU_Type))
    end
end

function handle_ll_control(opcode, params)
    if opcode == LL_PERIPHERAL_FEATURE_REQ then
        debug_log("LL_PERIPHERAL_FEATURE_REQ received")

        queue_ll_control_pdu(LL_FEATURE_RSP, buffer.new(8))
    elseif opcode == LL_LENGTH_REQ then
        debug_log("LL_LENGTH_REQ received")

        -- Send the same values back, as if we support whatever the client supports
        queue_ll_control_pdu(LL_LENGTH_RSP, params)
    else
        print("Unknown LL Control Opcode " .. string.format("0x%02X", opcode))
        assert(false)
    end
end

function handle_l2cap(packet)
    local pdu_length = packet[0] | (packet[1] << 8)
    local channel = packet[2] | (packet[3] << 8)

    debug_log("L2CAP PDU:")
    debug_log("  length", pdu_length)
    debug_log("  channel", channel)

    local payload = packet:slice(4, 4 + pdu_length)
    debug_log("  payload", payload)

    if channel == L2CAP_CHANNEL_ATT then
        handle_att(payload)
    end
end

local ATT_ERROR_RSP <const> = 0x01
local ATT_FIND_BY_TYPE_VALUE_REQ <const> = 0x06
local ATT_FIND_BY_TYPE_VALUE_RSP <const> = 0x07
local ATT_HANDLE_VALUE_NTF <const> = 0x1B

function handle_att(data)
    local packet = AttributePDU.decode(data)
    log_packet(packet, 3)

    if packet.Header.Auth ~= 0 then
        print("Auth flag is 1, unsupported")
        return
    end

    -- Vol 3 Part F Section 3.4
    if packet.Header.Method == ATT_FIND_BY_TYPE_VALUE_REQ then
        local req = AttributeATT_FIND_BY_TYPE_VALUE_REQ.decode(packet.Parameters)
        log_packet(req, 4)

        queue_attribute_packet(ATT_ERROR_RSP, AttributeATT_ERROR_RSP.encode {
            RequestOpcode = packet.Header.Method,
            AttributeHandle = req.StartingHandle,
            ErrorCode = 0x0A,
        })
    elseif packet.Header.Method == ATT_HANDLE_VALUE_NTF then
        local ntf = AttributeATT_HANDLE_VALUE_NTF.decode(packet.Parameters)
        log_packet(ntf, 4)
    else
        print("Unknown ATT Method " .. string.format("0x%02X", packet.Header.Method))
        assert(false)
    end
end

while true do
    pt:run({ seconds = 0.1, exitonevent = true })

    if #packet_queue == 0 then
        -- The peripheral can only send packets to us when it receives one, so if we have nothing to send we should still
        -- send an empty packet

        debug_log("[*] Sending empty LL packet")
        queue_ll_data_pdu(buffer.new(0))
    else
        debug_log("[*] Sending queued packet")
    end

    send(dequeue_packet())

    while true do
        local ev, data = pt:poll()
        if ev == nil then
            break
        end

        if ev == "radio_message" then
            comms_log_file:write("<- " .. #data .. " bytes: " .. tostring(data) .. "\n")

            local le_packet = LEUncodedPacket.decode(data:slice(0, -5))
            log_packet(le_packet, 0)

            if le_packet.access_address == adv_access_address then
                handle_advertising_channel(le_packet.pdu)
            else
                handle_data_physical_channel(le_packet.pdu)
            end
        end
    end
end
