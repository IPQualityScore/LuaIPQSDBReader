-- Copyright 2023 IPQualityScore LLC
local reader = require("ipqs.reader")
local record = require("ipqs.record")

local db = "IPQualityScore-IP-Reputation-Database-IPv6.ipqs"
local fileReader, readError = reader.open(db)
if readError then
  print(readError)
end
local ip = "2001:4860:4860::8844"
local rec, err = record.fetch(fileReader, ip)
if err then
  print(err)
else
  if rec then -- check for nil
    if rec.is_proxy then
      print(ip .. " is a proxy!")
    end
    print(rec.Country) -- query specific column
    print(rec:get("Organization")) -- query arbitrary column
    print("Latitude:", string.format("%.2f", rec.Latitude))
    -- dump table contents
    for k,v in pairs(rec) do
      print(k,v)
    end
    -- following will cause an error: "attempt to update a read-only table"
    -- rec.Country = "IN"
  else print("failed to fetch record")
  end
end
