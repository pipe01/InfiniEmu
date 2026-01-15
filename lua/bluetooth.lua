local pt = pinetime.new { firmware = "/home/pipe/git/InfiniTime/build/src/pinetime-app-1.16.0.out" }

local adv_access_address = buffer.new({ 0x8e, 0x89, 0xbe, 0xd6 }):reverse()

local our_address = buffer.new({ 0x0a, 0x1f, 0x63, 0x39, 0xb0, 0x47 }):reverse()

local our_access_address = buffer.new({ 0xaa, 0xbb, 0xcc, 0xdd }):reverse()

local sent_req = false

local Packet = require("lua/packet")

local pdu_types = {
    [0] = "ADV_IND",
    [1] = "ADV_DIRECT_IND",
    [2] = "ADV_NONCONN_IND",
    [3] = "SCAN_REQ",
    [4] = "SCAN_RSP",
    [5] = "CONNECT_IND",
    [6] = "ADV_SCAN_IND",
    [7] = "ADV_EXT_IND",
    [8] = "AUX_CONNECT_RSP",
}

local ADV_IND <const> = 0x00
local SCAN_REQ <const> = 0x03
local SCAN_RSP <const> = 0x04
local CONNECT_IND <const> = 0x05

local LL_PERIPHERAL_FEATURE_REQ <const> = 0x0E
local LL_FEATURE_RSP <const> = 0x09
local LL_LENGTH_REQ <const> = 0x14
local LL_LENGTH_RSP <const> = 0x15

local L2CAP_CHANNEL_ATT = 0x04

local fakeCRC = buffer.new({ 0xFF, 0xFF, 0xFF })

connected = false

local transmitSeqNum = 0
local nextExpectedSeqNum = 0

local last_packet_sent_time = 0
local packet_queue = {}

local LEUncodedPacket = Packet.define("LEUncodedPacket")
    :bytes("access_address", 4)
    :bytes_rest("pdu")
    :build()

local AdvertisingChannelPDU = Packet.define("AdvertisingChannelPDU")
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

local AdvertisingADV_IND = Packet.define("ADV_IND")
    :bytes("AdvA", 6)
    :bytes_rest("AdvData")
    :build()

local AdvertisingSCAN_REQ = Packet.define("SCAN_REQ")
    :bytes("ScanA", 6)
    :bytes("AdvA", 6)
    :build()

local AdvertisingSCAN_RSP = Packet.define("SCAN_RSP")
    :bytes("AdvA", 6)
    :bytes_rest("ScanRspData")
    :build()

local AdvertisingCONNECT_IND = Packet.define("CONNECT_IND")
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

local DataPhysicalChannelPDU = Packet.define("DataPhysicalChannelPDU")
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

local AttributePDU = Packet.define("AttributePDU")
    :bitfield("Header", 1, {
        { "Method", 6 },
        { "Command", 1 },
        { "Auth", 1 },
    })
    :bytes_rest("Parameters")
    :build()

local AttributeATT_FIND_BY_TYPE_VALUE_REQ = Packet.define("ATT_FIND_BY_TYPE_VALUE_REQ")
    :u16("StartingHandle")
    :u16("EndingHandle")
    :u16("AttributeType")
    :bytes_rest("AttributeValue")
    :build()

local AttributeATT_ERROR_RSP = Packet.define("ATT_ERROR_RSP")
    :u8("RequestOpcode")
    :u16("AttributeHandle")
    :u8("ErrorCode")
    :build()

local AttributeATT_HANDLE_VALUE_NTF = Packet.define("ATT_HANDLE_VALUE_NTF")
    :u16("AttributeHandle")
    :bytes_rest("AttributeValue")
    :build()

function send(packet)
    local with_crc = packet .. fakeCRC

    print("-> " .. #with_crc .. " bytes: " .. tostring(with_crc))
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
    print(DataPhysicalChannelPDU.tostring(packet))

    assert(#packet.payload == packet.header.Length)

    local llid = packet.header.LLID
    local nesn = packet.header.NESN
    local sn = packet.header.SN

    if sn == nextExpectedSeqNum then
        -- Good packet, increment
        nextExpectedSeqNum = 1 - nextExpectedSeqNum
        print("[*] Good packet received")
    else
        print("[*] Ignoring resent packet")
        return
    end

    if nesn == transmitSeqNum then
        print("[*] Last packet not acknowledged")
    else
        print("[*] Last packet acknowledged")

        -- Last packet was received, increment seqnum
        transmitSeqNum = 1 - transmitSeqNum
    end

    local is_data = llid == 1 or llid == 2
    if is_data then
        print("LL Data PDU")
    else
        print("LL Control PDU")
    end

    if is_data then
        if #packet.payload > 0 then
            handle_l2cap(packet.payload)
        else
            print("Ignoring empty packet")
        end
    else
        local opcode = packet.payload[0]
        local params = packet.payload:slice(1)

        handle_ll_control(opcode, params)
    end
end

function handle_advertising_channel(pdu)
    local adv_packet = AdvertisingChannelPDU.decode(pdu)
    print(AdvertisingChannelPDU.tostring(adv_packet))

    if adv_packet.header.PDU_Type == ADV_IND then
        local adv_ind = AdvertisingADV_IND.decode(adv_packet.payload)
        print(AdvertisingADV_IND.tostring(adv_ind))

        if not sent_req then
            sent_req = true

            queue_advertising_packet(SCAN_REQ, AdvertisingSCAN_REQ.encode {
                ScanA = our_address,
                AdvA = adv_ind.AdvA
            })
        end
    elseif adv_packet.header.PDU_Type == SCAN_RSP then
        local scan_rsp = AdvertisingSCAN_RSP.decode(adv_packet.payload)
        print(AdvertisingSCAN_RSP.tostring(scan_rsp))

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
        print("LL_PERIPHERAL_FEATURE_REQ received")

        queue_ll_control_pdu(LL_FEATURE_RSP, buffer.new(8))
    elseif opcode == LL_LENGTH_REQ then
        print("LL_LENGTH_REQ received")

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

    print("L2CAP PDU:")
    print("  length", pdu_length)
    print("  channel", channel)

    local payload = packet:slice(4, 4 + pdu_length)
    print("  payload", payload)

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
    print(AttributePDU.tostring(packet))

    if packet.Header.Auth ~= 0 then
        print("Auth flag is 1, unsupported")
        return
    end

    -- Vol 3 Part F Section 3.4
    if packet.Header.Method == ATT_FIND_BY_TYPE_VALUE_REQ then
        local req = AttributeATT_FIND_BY_TYPE_VALUE_REQ.decode(packet.Parameters)
        print(AttributeATT_FIND_BY_TYPE_VALUE_REQ.tostring(req))

        queue_attribute_packet(ATT_ERROR_RSP, AttributeATT_ERROR_RSP.encode {
            RequestOpcode = packet.Header.Method,
            AttributeHandle = req.StartingHandle,
            ErrorCode = 0x0A,
        })
    elseif packet.Header.Method == ATT_HANDLE_VALUE_NTF then
        local ntf = AttributeATT_HANDLE_VALUE_NTF.decode(packet.Parameters)
        print(AttributeATT_HANDLE_VALUE_NTF.tostring(ntf))
    else
        print("Unknown ATT Method " .. string.format("0x%02X", packet.Header.Method))
        assert(false)
    end
end

-- function build_l2cap_signaling_frame()

while true do
    pt:run({ seconds = 0.1, exitonevent = true })

    if pt:rantime() - last_packet_sent_time > 0.2 then
        if #packet_queue == 0 then
            print("[*] Sending empty LL packet")
            queue_ll_data_pdu(buffer.new(0))
        else
            print("[*] Sending queued packet")
        end

        send(dequeue_packet())
        if sentattresp then pt:startdebug() end
    end

    while true do
        local ev, data = pt:poll()
        if ev == nil then
            break
        end

        -- pt:run({ seconds = 0.05 })

        if ev == "radio_message" then
            print("<- " .. #data .. " bytes: " .. tostring(data))

            local le_packet = LEUncodedPacket.decode(data:slice(0, -5))
            print(LEUncodedPacket.tostring(le_packet))

            if le_packet.access_address == adv_access_address then
                handle_advertising_channel(le_packet.pdu)
            else
                handle_data_physical_channel(le_packet.pdu)
            end

            print()
        end
    end
end
