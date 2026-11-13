-- Prints one request field or call result: /lua/info.lua?<name>
local fields = {
    limit_req_body = function(r) return r.limit_req_body end,
    started = function(r) return r.started end,
    mpm_query = function(r) return r.mpm_query(9999) end,
    scoreboard_worker = function(r) return r:scoreboard_worker(100000, 0) end,
    md5 = function(r) return r:md5("abc") end,
    sha1 = function(r) return r:sha1("abc") end,
    base64_max = function(r)
        local ok = pcall(r.base64_encode, r, string.rep("x", 8 * 1024 * 1024))
        local over = pcall(r.base64_encode, r, string.rep("x", 8 * 1024 * 1024 + 1))
        return tostring(ok) .. "|" .. tostring(over)
    end,
}

function handle(r)
    local field = fields[r.args]
    if not field then return 404 end
    r.content_type = "text/plain"
    local value = field(r)
    r:puts(tostring(value), "\n")
    return apache2.OK
end
