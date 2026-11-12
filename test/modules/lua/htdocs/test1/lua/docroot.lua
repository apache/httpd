-- Sets a document root from a string nothing else refers to, lets Lua
-- collect it, then reads it back.  /lua/docroot.lua?<setter>
local LEN = 1000

local function fresh(tag)
    -- A string no other value refers to.
    return table.concat({string.rep("x", LEN), tag, tostring(os.time())})
end

local function churn()
    collectgarbage()
    collectgarbage()
    local t = {}
    for i = 1, 4096 do t[i] = string.rep("y", LEN + 12) .. i end
    return t
end

local setters = {
    set_document_root = function(r)
        r:set_document_root(fresh("/root"))
        local _ = churn()
        return r.document_root
    end,
    set_context_info = function(r)
        r:set_context_info(fresh("/prefix"), fresh("/root"))
        local _ = churn()
        return r.context_prefix .. "|" .. r.context_document_root
    end,
}

function handle(r)
    local setter = setters[r.args]
    if not setter then return 404 end
    local got = setter(r):gsub("%d+", "N")
    r.content_type = "text/plain"
    r:puts(got, "\n")
    return apache2.OK
end
