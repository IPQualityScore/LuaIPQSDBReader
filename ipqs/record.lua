-- Copyright 2023 IPQualityScore LLC

-- record contains the information about an IP address
local Record = {}

-- parse the bytes at the leaf of the tree into a record
-- returns a Record "object", including associated methods
local function parse (reader, position)
  local flag = require("ipqs.bitmasks")
  reader.file_:seek("set", position)
  local raw = reader.file_:read(reader.recordLength_)
  local nextByte = 1 -- both kinds of record share a common bitmask byte
  local record = {}
  -- Binary Option begin
  if reader.binary_option then -- record starts with 3 bitmask bytes
    -- Byte 0
    local byteZero = string.unpack("B", raw, 1)
    record.is_proxy = byteZero & flag.IS_PROXY == flag.IS_PROXY
    record.is_vpn = byteZero & flag.IS_VPN == flag.IS_VPN
    record.is_tor = byteZero & flag.IS_TOR == flag.IS_TOR
    record.is_crawler = byteZero & flag.IS_CRAWLER == flag.IS_CRAWLER
    record.is_bot = byteZero & flag.IS_BOT == flag.IS_BOT
    record.recent_abuse = byteZero & flag.RECENT_ABUSE == flag.RECENT_ABUSE
    record.is_blacklisted = byteZero & flag.IS_BLACKLISTED == flag.IS_BLACKLISTED
    record.is_private = byteZero & flag.IS_PRIVATE == flag.IS_PRIVATE
    -- Byte 1
    local byteOne = string.unpack("B", raw, 2)
    record.is_mobile = byteOne & flag.IS_MOBILE == flag.IS_MOBILE
    record.has_open_ports = byteOne & flag.HAS_OPEN_PORTS == flag.HAS_OPEN_PORTS
    record.is_hosting_provider =
      byteOne & flag.IS_HOSTING_PROVIDER == flag.IS_HOSTING_PROVIDER
    record.active_vpn = byteOne & flag.ACTIVE_VPN == flag.ACTIVE_VPN
    record.active_tor = byteOne & flag.ACTIVE_TOR == flag.ACTIVE_TOR
    record.public_access_point =
      byteOne & flag.PUBLIC_ACCESS_POINT == flag.PUBLIC_ACCESS_POINT
    -- Binary Option end
    nextByte = 3
  end
  local commonByte = string.unpack("B", raw, nextByte)
  -- common byte has two unique bit fields: Connection Type, and Abuse Velocity
  -- Connection Type
  local connectionType = commonByte & flag.CONNECTION_MASK
  if connectionType == flag.RESIDENTIAL then
    connectionType = "Residential"
  elseif connectionType == flag.MOBILE then
    connectionType = "Mobile"
  elseif connectionType == flag.CORPORATE then
    connectionType = "Corporate"
  elseif connectionType == flag.DATA_CENTER then
    connectionType = "Data Center"
  elseif connectionType == flag.EDUCATION then
    connectionType = "Education"
  else connectionType = "Unknown"
  end
  record.connection_type = connectionType
  -- Abuse Velocity
  local abuseVelocity = commonByte & flag.ABUSE_MASK
  if abuseVelocity == flag.ABUSE_LOW then
    abuseVelocity = "low"
  elseif abuseVelocity == flag.ABUSE_MEDIUM then
    abuseVelocity = "medium"
  elseif abuseVelocity == flag.ABUSE_HIGH then
    abuseVelocity = "high"
  else abuseVelocity = "none"
  end
  record.abuse_velocity = abuseVelocity

  nextByte = nextByte + 1 -- done with bitmask bytes

  -- parse column data, using associated data type from column headers
  for _,v in ipairs(reader.columns_) do
    local columnName = v.name
    local value -- to be associated with column
    -- STRING
    if v.data == "STRING_DATA" then
      -- 4-byte pointer to string data
      local p = string.unpack("<I4", raw, nextByte)
      nextByte = nextByte + 4
      reader.file_:seek("set", p)
      local stringLength = reader.file_:read(1)
      stringLength = string.unpack("<I1", stringLength)
      if not stringLength then
        return nil, "failed to determine length of string data (EID 2)"
      end
      value = reader.file_:read(stringLength)
    -- SMALL INT
    elseif v.data == "SMALL_INT_DATA" then
      -- 1-byte unsigned int
      value = string.unpack("<I1", raw, nextByte)
      nextByte = nextByte + 1
    elseif v.data == "INT_DATA" then
      -- 4-byte unsigned int
      value = string.unpack("<I4", raw, nextByte)
      nextByte = nextByte + 4
    elseif v.data == "FLOAT_DATA" then
      value = string.unpack("<f", raw, nextByte) -- NOTE! assumes native size!
      nextByte = nextByte + 4
    end
    record[columnName] = value
  end

  -- return value associated with arbitrary column
  record.get = function(self, column)
    return self[column]
  end

  -- create read-only "proxy" table (see Programming in Lua, 4th, ch. 20.4)
  local proxy = {}
  local mt = { -- create metatable
    __index = record,
    __pairs = function ()
      return next, record, nil
    end,
    __newindex = function (t, k, v)
      error("attempt to update a read-only table", 2)
    end
  }
  setmetatable(proxy, mt)
  return proxy
end

-- find record in tree if it exists and return it
-- else return nil and error message
function Record.fetch (reader, ip)
  local parser = require("ipqs.ip") -- ip parser

  -- check that IP version matches file
  if string.find(ip, ":") and not reader.is_ipv6 then
    return nil, "error: attempted to lookup an IPv6 address using an IPv4 database"
  end
  if string.find(ip, "%.") and reader.is_ipv6 then
    return nil, "error: attempted to lookup an IPv4 address using an IPv6 database"
  end

  -- get binary representation
  local literal, err = parser.parse(ip)
  if err then
    return nil, err
  end

  -- traverse tree
  local filePosition = reader.treeStart_+5 -- tree header is 5 bytes
  local previous = {} -- used to go back up tree
  local position = 1 -- bit within ip address (Lua indexing starts at 1)
  local next -- byte offset (position within tree)
  for l = 1, 257 do -- following Go implementation: "for l:=0;l<257;l++ {..."
    previous[position] = filePosition
    if position > #literal then
      print(position)
      return nil, "invalid or nonexistent IP address specified for lookup (EID: 3)"
    end
    reader.file_:seek("set", filePosition)
    local branches = reader.file_:read(8)
    if not branches then
      return nil, "invalid or nonexistent IP address specified for lookup (EID: 4)"
    end
    local left = string.unpack("<I4", branches, 1)
    local right = string.unpack("<I4", branches, 5)
    if literal then
      if literal[position] then -- bit is 1
        next = right
      else next = left -- bit is 0
      end
    else return nil, "ip error: failed to parse IP address (EID: 5)"
    end
    if next > reader.filesize_ then
      return nil, "flat file error: next filePosition greater than file size (EID: 6)"
    end
    if next == 0 then -- exact IP address not present
      if reader.is_blacklist then
        return nil, "IP address not found"
      end
        -- go back up tree, searching for CIDR block
      for i = 0, position do
        if literal[position-i] then -- if bit is "1"
          literal[position-i] = false -- set to "0"
          for n = (position - i + 1), #literal do -- set all following bits to "1"
            literal[n] = true
          end
          position = position - i
          filePosition = previous[position]
          break
        end
      end
      goto continue
    end
    if next >= reader.treeEnd_ then -- should be at a record
      return parse(reader, next) -- this should be a "proper tail call"
    end
    filePosition = next
    position = position + 1
      ::continue::
  end
  return nil, "invalid or nonexistent IP address specified for lookup (EID 7)"
end

return Record
