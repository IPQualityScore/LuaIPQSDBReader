-- Copyright 2023 IPQualityScore LLC

local M = {}

local function ip_type (ip)

  -- IPv4
  local octets = { string.match(ip, "^(%d+)%.(%d+)%.(%d+)%.(%d+)$") }
  if #octets == 4 then
    for k, v in ipairs(octets) do
      octets[k] = math.tointeger(v)
      if octets[k] > 255 then
        return nil, "invalid IP address - octet greater than 255"
      end
    end
    return octets, true
  end

  -- IPv6
  local segments = {}
  for segment in string.gmatch(ip, "([a-fA-F0-9)]+)") do
    segments[#segments + 1] = segment -- collect hex segments
  end
  if #segments > 8 or string.find(ip, "::.*::") or string.find(ip, ":::") then
    return nil, "invalid IP address"
  end
  if #segments < 8 and string.find(ip, "::") then -- address is abbreviated
    local zeros = 8 - #segments -- we need to expand it
    local full_ip = string.gsub(ip, "::", string.rep(":0:", zeros))
    segments = {} -- reset segments table and collect again
    for segment in string.gmatch(full_ip, "([a-fA-F0-9)]+)") do
      segments[#segments + 1] = segment
    end
  else
    return nil, "invalid IP address"
  end
  for k, v in ipairs(segments) do
    local num = tonumber(v, 16)
    if num > 0xFFFF then
      return nil, "invalid IP address - segment greater than FFFF"
    end
    segments[k] = num
  end
  return segments, false
end

-- convert address to binary representation (booleans)
-- IPv6
local function binrepv6 (segment)
  local mask = 0x8000
  local t = {}
  for _ = 1, 16 do
    t[#t+1] = segment & mask ~= 0
    mask = mask >> 1
  end
  return t
end
-- IPv4
local function binrepv4 (octet)
  local mask = 0x80
  local t = {}
  for _ = 1, 8 do
    t[#t+1] = octet & mask ~= 0
    mask = mask >> 1
  end
  return t
end

-- parse the IP address and return binary representation as table
function M.parse (ip)
  local groups, ipv4 = ip_type(ip)
  local t = {}
  if groups and ipv4 then
    -- IPv4
    for _, octet in ipairs(groups) do
      local bits = binrepv4(octet)
      table.move(bits, 1, #bits, #t+1, t)
    end
  elseif groups then
    -- IPv6
    for k, segment in ipairs(groups) do
      local bits = binrepv6(segment)
      table.move(bits, 1, #bits, #t+1, t)
    end
  else
    return nil, "invalid IP"
  end
  return t
end

return M
