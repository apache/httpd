-- Reads and writes request tables through separate accesses of the
-- same field, and prints the options and overrides strings.
function handle(r)
    r.notes["lua-a"] = "1"
    local n = r.notes
    n["lua-b"] = "2"
    r.headers_out["X-Lua-Notes"] = r.notes["lua-a"] .. n["lua-b"]
    r.headers_out["X-Lua-Host"] = r.headers_in["Host"]
    r.content_type = "text/plain"
    r:puts(r.options, "|", r.allowoverrides, "\n")
    return apache2.OK
end
