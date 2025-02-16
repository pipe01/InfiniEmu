local pt = pinetime.new { firmware = "pinetime-app-1.15.0.out" }

local adv_access_address = buffer.new({ 0x8e, 0x89, 0xbe, 0xd6 }):reverse()

local our_address = buffer.new({ 0x0a, 0x1f, 0x63, 0x39, 0xb0, 0x47 }):reverse()

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

function build_adv_pdu(pdu_type, payload)
    -- https://www.bluetooth.com/wp-content/uploads/Files/Specification/HTML/Core-54/out/en/low-energy-controller/link-layer-specification.html#UUID-22b4515e-1d0c-1503-7135-af187bccf617

    -- CRC doesn't matter, our radio peripheral doesn't check it
    return adv_access_address .. buffer.new({ pdu_type, #payload }) .. payload .. buffer.new({ 0xFF, 0xFF, 0xFF })
end

function build_scan_req_pdu(adv_address)
    return build_adv_pdu(3, our_address .. adv_address)
end

while true do
    pt:run({ seconds = 1, exitonevent = true })

    while true do
        local ev, data = pt:poll()
        if ev == nil then
            break
        end

        if ev == "radio_message" then
            print(data)

            local access_address = data:slice(0, 4)
            local pdu = data:slice(4)

            if access_address == adv_access_address then
                -- Advertising channel PDU

                local ll_header = pdu:slice(0, 2)
                local pdu_type = ll_header[0] & 0x0f
                local payload = pdu:slice(2)

                print("pdu_type", pdu_types[pdu_type])
                print("  address", access_address)

                if pdu_type == 0 then -- ADV_IND
                    local adv_address = payload:slice(0, 6)

                    local len_16bit_uuids = payload[9]
                    local len_128bit_uuids = payload[10 + len_16bit_uuids]

                    print("  adv_address", adv_address)
                    print("  num_16bit_uuids", len_16bit_uuids)
                    print("  num_128bit_uuids", len_128bit_uuids)

                    if not sent_req then
                        sent_req = true

                        pt:sendradio(build_scan_req_pdu(adv_address))
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
                else
                    os.exit(0)
                end
            end

            print()
        end
    end
end
