-- r:requestbody() in several modes: /lua/body.lua?<mode>
--   read     the body, with its length, md5 and the child's RSS growth
--   readmax  the body with a 100 byte limit
--   file     the body stored to a file, with its length and md5
--   filemax  the body stored to a file with a 100 byte limit
--   fileover the body stored over the file left by an earlier request

local function rss()
    collectgarbage()
    for line in io.lines("/proc/self/status") do
        local kb = line:match("^VmRSS:%s+(%d+)")
        if kb then return tonumber(kb) end
    end
    return 0
end

function handle(r)
    local mode = r.args
    local path = r.document_root .. "/lua/upload.out"
    local res, extra
    r.content_type = "text/plain"
    if mode == "read" then
        local before = rss()
        local body, len = r:requestbody()
        local growth = rss() - before
        r:puts(tostring(len), " ", body and r:md5(body) or "-", " ",
               growth, "\n")
    elseif mode == "readmax" then
        res = {r:requestbody(nil, 100)}
        r:puts(tostring(res[2] and res[1] and #res[1] or res[1]), "|",
               tostring(res[2]), "\n")
    elseif mode == "file" or mode == "filemax" or mode == "fileover" then
        if mode ~= "fileover" then os.remove(path) end
        res = {r:requestbody(path, mode == "filemax" and 100 or nil)}
        local f = io.open(path, "rb")
        extra = f and r:md5(f:read("*a")) or "-"
        if f then f:close() end
        r:puts(tostring(res[1]), "|", tostring(res[2]), "|", extra, "\n")
    else
        return 404
    end
    return apache2.OK
end
