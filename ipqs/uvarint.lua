-- Copyright 2023 IPQualityScore LLC
local MAXLEN = 10
local M = {}
function M.uvarint(bytes)
    local x, s = 0, 0
    for i = 1, #bytes do
        if i == MAXLEN then
            return 0, -(i + 1) -- overflow
        end
        local b = string.unpack("B", bytes, i)
        if b < 0x80 then
            if i == MAXLEN - 1 and b > 1 then
                return 0, -(i + 1) -- overflow
            end
            return x | b << s, i + 1
        end
        x = x | b & 0x7f << s
        s = s + 7
    end
    return 0, 0
end

return M
