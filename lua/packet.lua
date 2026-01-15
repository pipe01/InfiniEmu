local Packet = {}

----------------------------------------------------------------
-- Buffer reader / writer
----------------------------------------------------------------

local function writer(size)
    return {
        buf = buffer.new(size),
        pos = 1,

        write_u8 = function(self, v)
            self:ensure_size(self.pos)
            self.buf[self.pos - 1] = v & 0xFF
            self.pos = self.pos + 1
        end,

        write_bytes = function(self, src)
            self:ensure_size(self.pos + #src - 1)
            for i = 1, #src do
                self.buf[self.pos - 1] = src[i]
                self.pos = self.pos + 1
            end
        end,

        ensure_size = function(self, newsize)
            if #self.buf < newsize then
                self.buf:resize(newsize)
            end
        end,
    }
end

local function reader(buf)
    return {
        buf = buf,
        pos = 1,

        read_u8 = function(self)
            local v = self.buf[self.pos - 1]
            self.pos = self.pos + 1
            return v
        end,

        read_bytes = function(self, n)
            local s = self.buf:slice(self.pos - 1, self.pos + n - 1)
            self.pos = self.pos + n
            return s
        end,
    }
end

----------------------------------------------------------------
-- Types
----------------------------------------------------------------

local Types = {}

Types.u8 = {
    size = 1,
    write = function(w, v)
        w:write_u8(v)
    end,
    read = function(r)
        return r:read_u8()
    end
}

Types.u16 = {
    size = 2,
    write = function(w, v)
        w:write_u8(v & 0xFF)
        w:write_u8((v >> 8) & 0xFF)
    end,
    read = function(r)
        local lo = r:read_u8()
        local hi = r:read_u8()
        return lo | (hi << 8)
    end
}

Types.string = function(len)
    return {
        size = len,
        write = function(w, v)
            v = v or ""
            for i = 1, len do
                w:write_u8(v:byte(i) or 0)
            end
        end,
        read = function(r)
            local buf = r:read_bytes(len)
            -- trim trailing NULs
            local last = len
            while last > 0 and buf[last] == 0 do
                last = last - 1
            end
            local chars = {}
            for i = 1, last do
                chars[i] = string.char(buf[i])
            end
            return table.concat(chars)
        end
    }
end

Types.bytes = function(len)
    return {
        size = len,

        write = function(w, v)
            -- v may be a buffer or a Lua array
            if v then
                for i = 1, len do
                    local byte = v[i - 1] or 0
                    w:write_u8(byte)
                end
            else
                -- write all zeros
                for i = 1, len do
                    w:write_u8(0)
                end
            end
        end,

        read = function(r)
            -- return a new buffer of exactly len bytes
            return r:read_bytes(len)
        end
    }
end

Types.bytes_rest = {
    size = nil,  -- variable

    write = function(w, v)
        if not v then return end
        for i = 1, #v do
            w:write_u8(v[i - 1])
        end
    end,

    read = function(r)
        local remaining = #r.buf - r.pos + 1
        if remaining <= 0 then
            return buffer.new(0)
        end
        return r:read_bytes(remaining)
    end
}

Types.bitfield = function(byte_size, layout)
    local fields = {}
    local bit_pos = 0
    local total_bits = byte_size * 8

    for i, entry in ipairs(layout) do
        local name = entry[1]
        local bits = entry[2]

        if bit_pos + bits > total_bits then
            error("bitfield overflow")
        end

        fields[#fields + 1] = {
            name = name,
            bits = bits,
            shift = bit_pos,
            mask = (1 << bits) - 1
        }

        bit_pos = bit_pos + bits
    end

    return {
        size = byte_size,

        write = function(w, v)
            local value = 0
            for _, f in ipairs(fields) do
                local fv = (v and v[f.name]) or 0
                value = value | ((fv & f.mask) << f.shift)
            end

            -- little endian byte order
            for i = 0, byte_size - 1 do
                w:write_u8((value >> (i * 8)) & 0xFF)
            end
        end,

        read = function(r)
            local value = 0
            for i = 0, byte_size - 1 do
                value = value | (r:read_u8() << (i * 8))
                -- value = (value << 8) | r:read_u8()
            end

            local out = {}
            for _, f in ipairs(fields) do
                out[f.name] = (value >> f.shift) & f.mask
            end
            return out
        end
    }
end

----------------------------------------------------------------
-- Packet builder
----------------------------------------------------------------

local Builder = {}
Builder.__index = Builder

function Builder:u8(name)
    self.fields[#self.fields + 1] = { name, Types.u8 }
    self.size = self.size + 1
    return self
end

function Builder:u16(name)
    self.fields[#self.fields + 1] = { name, Types.u16 }
    self.size = self.size + 2
    return self
end

function Builder:string(name, len)
    self.fields[#self.fields + 1] = { name, Types.string(len) }
    self.size = self.size + len
    return self
end

function Builder:bytes(name, len)
    self.fields[#self.fields + 1] = { name, Types.bytes(len) }
    self.size = self.size + len
    return self
end

function Builder:bytes_rest(name)
    self.fields[#self.fields + 1] = { name, Types.bytes_rest }
    self.has_variable = true
    return self
end

function Builder:bitfield(name, byte_size, layout)
    self.fields[#self.fields + 1] = {
        name,
        Types.bitfield(byte_size, layout)
    }
    self.size = self.size + byte_size
    return self
end

local function indent(n)
    return string.rep("  ", n)
end

local function format_value(v, depth)
    depth = depth or 0

    -- buffer → hex
    if type(v) == "userdata" and #v then
        local bytes = {}
        for i = 1, #v do
            bytes[#bytes + 1] = string.format("%02X", v[i - 1])
        end
        return "<buffer " .. #v .. " bytes: " .. table.concat(bytes, " ") .. ">"
    end

    -- table (bitfield or nested)
    if type(v) == "table" then
        local lines = { "{" }
        for k, val in pairs(v) do
            lines[#lines + 1] =
                indent(depth + 1) ..
                tostring(k) .. " = " ..
                format_value(val, depth + 1) .. ","
        end
        lines[#lines + 1] = indent(depth) .. "}"
        return table.concat(lines, "\n")
    end

    -- string
    if type(v) == "string" then
        return string.format("%q", v)
    end

    return tostring(v)
end

----------------------------------------------------------------
-- Finalize packet
----------------------------------------------------------------

function Builder:build()
    local fields = self.fields
    local total_size = nil
    local struct = {}
    local builder = self

    if not self.has_variable then
        total_size = self.size
    end

    function struct.encode(tbl)
        local w = writer(total_size or 0)

        for _, f in ipairs(fields) do
            f[2].write(w, tbl[f[1]])
        end

        return w.buf
    end

    function struct.decode(buf)
        local r = reader(buf)
        local out = {}
        for _, f in ipairs(fields) do
            out[f[1]] = f[2].read(r)
        end

        return setmetatable(out, {
            __tostring = function(t)
                local lines = { builder.name .. " {" }
                for _, f in ipairs(fields) do
                    local name = f[1]
                    local value = t[name]
                    lines[#lines + 1] = "  " .. name .. " = " .. format_value(value, 1) .. ","
                end
                lines[#lines + 1] = "}"
                return table.concat(lines, "\n")
            end
        })
    end

    function struct.size()
        return total_size
    end

    function struct.tostring(tbl)
        local lines = { self and self.name or "Packet", " {" }

        for _, f in ipairs(fields) do
            local name = f[1]
            local value = tbl[name]
            lines[#lines + 1] =
                "  " .. name .. " = " .. format_value(value, 1) .. ","
        end

        lines[#lines + 1] = "}"
        return table.concat(lines, "\n")
    end

    return struct
end

----------------------------------------------------------------
-- Public API
----------------------------------------------------------------

function Packet.define(name)
    return setmetatable({
        name = name,
        fields = {},
        size = 0
    }, Builder)
end

return Packet
