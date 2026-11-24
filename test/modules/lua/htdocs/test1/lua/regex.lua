-- r:regex() with as many capture groups as it accepts: prints the
-- last capture.
function handle(r)
    local n = tonumber(r.args)
    local m = r:regex(string.rep("x", n), string.rep("(x)", n))
    r.content_type = "text/plain"
    r:puts(tostring(m and m[n]), "\n")
    return apache2.OK
end
