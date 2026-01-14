local pt = pinetime.new { firmware = "/home/pipe/git/InfiniTime/build/src/pinetime-app-1.16.0.out" }

local adv_access_address = buffer.new({ 0x8e, 0x89, 0xbe, 0xd6 }):reverse()

local our_address = buffer.new({ 0x0a, 0x1f, 0x63, 0x39, 0xb0, 0x47 }):reverse()

local our_access_address = buffer.new({ 0xaa, 0xbb, 0xcc, 0xdd }):reverse()

local sent_req = false

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

local L2CAP_CHANNEL_ATT = 0x04

local fakeCRC = buffer.new({ 0xFF, 0xFF, 0xFF })

local sent_test = false
local connected = false
local peripheral_access_addr = nil

local transmitSeqNum = 0
local nextExpectedSeqNum = 0

local last_packet_sent_time = 0
local packet_queue = {}

function send(packet)
    print("sending " .. #packet .. " bytes: ", packet)
    pt:sendradio(packet)
    last_packet_sent_time = pt:rantime()
end

function queue_packet(packet)
    table.insert(packet_queue, packet)
end

function build_adv_pdu(pdu_type, payload)
    -- https://www.bluetooth.com/wp-content/uploads/Files/Specification/HTML/Core-54/out/en/low-energy-controller/link-layer-specification.html#UUID-22b4515e-1d0c-1503-7135-af187bccf617

    -- CRC doesn't matter, our radio peripheral doesn't check it
    return adv_access_address .. buffer.new({ pdu_type, #payload }) .. payload .. fakeCRC
end

function le16(value)
    return buffer.new({ value & 0xFF, (value >> 8) & 0xFF })
end

function fromle16(buffer, start)
    return buffer[start] | (buffer[start + 1] << 8)
end

function build_scan_req_pdu(adv_address)
    return build_adv_pdu(3, our_address .. adv_address)
end

function build_connect_ind_pdu(adv_address, AA, CRCInit, WinSize, WinOffset, Interval, Latency, Timeout, ChM, Hop, SCA)
    InitA = buffer.new({ 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA })
    LLData = AA .. CRCInit .. buffer.new({ WinSize }) .. le16(WinOffset) .. le16(Interval) .. le16(Latency) .. le16(Timeout) .. ChM .. buffer.new({ (Hop << 5) | SCA })

    return build_adv_pdu(5, InitA .. adv_address .. LLData)
end

-- Vol 6 Part B Section 2.4
function build_data_physical_pdu(llid, adv_address, payload)
    local nesn = nextExpectedSeqNum
    local sn = transmitSeqNum
    local md = 0
    local cp = 0
    local rfu = 0

    assert(#adv_address == 4)

    print(adv_address, payload, sn)

    return adv_address .. buffer.new({
        llid | nesn << 2 | sn << 3 | md << 4 | cp << 5 | rfu << 6,
        #payload & 0xFF,
    }) .. payload .. fakeCRC
end

function build_ll_control_pdu(opcode, params)
    return build_data_physical_pdu(3, our_access_address, buffer.new({ opcode }) .. params)
end

-- function build_att_pdu()

-- Vol 6 Part B Section 2.4
function handle_data_physical_channel(packet)
    local llid = packet[0] & 0x03
    local nesn = (packet[0] >> 2) & 0x01
    local sn = (packet[0] >> 3) & 0x01
    local md = (packet[0] >> 4) & 0x01
    local cp = (packet[0] >> 5) & 0x01
    local rfu = (packet[0] >> 6) & 0x03
    local length = packet[1]

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
        -- LL Data PDU
        print("LL Data PDU:")
    else
        -- LL Control PDU
        print("LL Control PDU:")
    end

    print("  llid", llid)
    print("  nesn", nesn)
    print("  sn", sn)
    print("  md", md)
    print("  cp", cp)
    print("  length", length)

    if is_data then
        local payload = packet:slice(2, 2 + length)
        print("  payload: ", payload)

        handle_l2cap(payload)
    else
        local opcode = packet[2]
        local params = packet:slice(3, 2 + length)
        print("  opcode: ", opcode)
        print("  params: ", params)
        
        handle_ll_control(opcode, params)
    end
end

function handle_ll_control(opcode, params)
    if opcode == 0x0E then -- LL_PERIPHERAL_FEATURE_REQ
        -- LL_FEATURE_RSP
        queue_packet(build_ll_control_pdu(0x09, buffer.new(8)))
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

local ATT_FIND_BY_TYPE_VALUE_REQ <const> = 0x06
local ATT_FIND_BY_TYPE_VALUE_RSP <const> = 0x07
local ATT_ERROR_RSP <const> = 0x01

function handle_att(packet)
    local auth_flag = packet[0] >> 7
    if auth_flag ~= 0 then
        print("Auth flag is 1, unsupported")
        return
    end

    local method = packet[0] & 0x3F
    local params = packet:slice(1, #packet)

    print("ATT PDU:")
    print("  method", method)
    print("  params", params)

    -- Vol 3 Part F Section 3.4
    if method == ATT_FIND_BY_TYPE_VALUE_REQ then
        local starting_handle = fromle16(params, 0)
        local ending_handle = fromle16(params, 2)
        local attribute_type = fromle16(params, 4)
        local attribute_value = params:slice(6)

        print("  ATT_FIND_BY_TYPE_VALUE_REQ")
        print("    starting_handle", starting_handle)
        print("    ending_handle", ending_handle)
        print("    attribute_type", attribute_type)
        print("    attribute_value", attribute_value)
    end
end

-- function build_l2cap_signaling_frame()

local empty_counter = 0
while true do
    pt:run({ seconds = 0.4, exitonevent = true })

    if pt:rantime() - last_packet_sent_time > 0.4 then
        local packet
        if #packet_queue > 0 then
            print("[*] Sending queued packet")
            packet = table.remove(packet_queue, 1)
        else
            print("[*] Sending empty LL packet")
            packet = build_data_physical_pdu(1, our_access_address, buffer.new(0))
        end

        send(packet)
    end

    while true do
        local ev, data = pt:poll()
        if ev == nil then
            break
        end

        pt:run({ seconds = 0.05 })

        if ev == "radio_message" then
            print(data)

            local access_address = data:slice(0, 4)
            local pdu = data:slice(4)

            if access_address == adv_access_address then
                -- Advertising channel PDU

                local ll_header = pdu:slice(0, 2)
                local pdu_type = ll_header[0] & 0x0f
                local payload = pdu:slice(2)

                print("payload", payload)

                print("pdu_type", pdu_types[pdu_type], pdu_type)
                print("  address", access_address)

                if pdu_type == 0 then -- ADV_IND
                    local adv_address = payload:slice(0, 6)
                    peripheral_access_addr = adv_address

                    local len_16bit_uuids = payload[9]
                    local len_128bit_uuids = payload[10 + len_16bit_uuids]

                    print("  adv_address", adv_address)
                    print("  num_16bit_uuids", len_16bit_uuids)
                    print("  num_128bit_uuids", len_128bit_uuids)

                    if not sent_req then
                        sent_req = true

                        packet = build_scan_req_pdu(adv_address)
                        print("sending SCAN_REQ: " .. tostring(packet))
                        queue_packet(packet)
                    else
                        -- pt:run({ seconds = 1.5 })
                        -- send(buffer.new(15))
                        -- pt:startdebug()
                    end
                elseif pdu_type == 4 then -- SCAN_RSP
                    local adv_address = payload:slice(0, 6)
                    local scan_data = payload:slice(6)

                    local length = scan_data[0]
                    local type = scan_data[1]
                    local value = scan_data:slice(2, 2 + length - 1)

                    print("  adv_address", adv_address)
                    print("  type", type)
                    print("  value", value:toutf8())

                    packet = build_connect_ind_pdu(
                        adv_address,
                        our_access_address,                     -- AA
                        buffer.new({ 0xBB, 0xBB, 0xBB }),       -- CRCInit
                        1800,                                   -- WinSize
                        0,                                      -- WinOffset
                        2000,                                   -- Interval
                        1,                                      -- Latency
                        1600,                                   -- Timeout
                        buffer.new({ 0xCC, 0xCC, 0xCC, 0xCC, 0xCC }), -- ChM
                        7,                                      -- Hop
                        0                                       -- SCA
                    )
                    print("sending CONNECT_IND: " .. tostring(packet))
                    queue_packet(packet)
                    -- pt:startdebug()

                    connected = true
                else
                    os.exit(0)
                end
            else
                handle_data_physical_channel(pdu)
            end

            print()
        end
    end
end
