-- Copyright 2023 IPQualityScore LLC

local Reader = {}

local IPV4 = 0x1
local IPV6 = 0x2
local BLACKLIST = 0x4
local BINARY_OPTION = 0x80
local VERSION = 1

-- data type bitmask for column
local bitmasks = {
    STRING_DATA = 0x08,
    SMALL_INT_DATA = 0x10,
    INT_DATA = 0x20,
    FLOAT_DATA = 0x40
}

function Reader.open(filename)
  local reader = {}
    local f = assert(io.open(filename, "rb"))
    f:seek("set") -- move to beginning of file
    local header = f:read(11)

    -- Header Byte "Zero"
    reader.is_ipv4 = false
    local byte_zero = string.unpack("B", header, 1)
    if (byte_zero & IPV4 == IPV4) then reader.is_ipv4 = true end

    reader.is_ipv6 = false
    if (byte_zero & IPV6 == IPV6) then reader.is_ipv6 = true end

    if reader.is_ipv6 == reader.is_ipv4 then
      return nil, "reader error: corrupt or invalid file (EID 1)"
    end

    reader.is_blacklist = false
    if (byte_zero & BLACKLIST == BLACKLIST) then reader.is_blacklist = true end

    reader.binary_option = false
    if (byte_zero & BINARY_OPTION == BINARY_OPTION) then reader.binary_option = true end

    local version = string.unpack("B", header, 2)
    assert(version == VERSION, "file version is incompatible with this reader")

    local M = require("ipqs.uvarint")
    local headerSize = M.uvarint(string.sub(header, 3, 5))
    reader.treeStart_ = headerSize

    reader.recordLength_ = string.unpack("<I2", header, 6)
    reader.filesize_ = string.unpack("<I4", header, 8)

    local numColumns = (headerSize - 11) // 24

    f:seek("set", 11) -- move to beginning of column pairs
    local columnPairs = f:read(headerSize - 11)
    reader.columns_ = {}
    local next = 1
    for _ = 1, numColumns do
        local columnName = string.unpack("z", columnPairs, next)
        local dataType
        local data = string.unpack("B", columnPairs, next + 23)
        if (data & bitmasks.STRING_DATA == bitmasks.STRING_DATA) then
            dataType = "STRING_DATA"
        elseif (data & bitmasks.SMALL_INT_DATA == bitmasks.SMALL_INT_DATA) then
            dataType = "SMALL_INT_DATA"
        elseif (data & bitmasks.INT_DATA == bitmasks.INT_DATA) then
            dataType = "INT_DATA"
        elseif (data & bitmasks.FLOAT_DATA == bitmasks.FLOAT_DATA) then
            dataType = "FLOAT_DATA"
        end
        reader.columns_[#reader.columns_ + 1] = {name = columnName, data = dataType}
        next = next + 24
    end

    -- tree header
    f:seek("set", headerSize)
    local treeHeader = f:read(5)
    reader.treeSize_ = string.unpack("<I4", treeHeader, 2)
    reader.treeEnd_ = reader.treeStart_ + reader.treeSize_
    reader.file_ = f

    local proxy = {}
    local mt = {
      __index = reader,
      __newindex = function (t, k, v)
        error("attempt to update a read-only table", 2)
      end
    }
    setmetatable(proxy, mt)
  return proxy
end

return Reader
