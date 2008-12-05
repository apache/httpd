module("helpers", package.seeall)

local io = require("io")
local http = require("socket.http")
local string = require("string")

base_url = "http://localhost"

function get(uri)
  return http.request(base_url .. uri)  
end

function post(uri, body)
  local function do_it(body)
    local flat
    if (type(body) == "table") then
      i = 1
      for k, v in pairs(body) do
        if i == 1 then 
          flat = k .. "=" ..v 
        else
          flat = flat .. "&" .. k .. "=" .. v
        end
        i = i + 1
      end
    else
      flat = body;
    end
    return http.request(base_url .. uri, flat) 
  end
  if body then
    return do_it(body)
  else
    return do_it
  end
end