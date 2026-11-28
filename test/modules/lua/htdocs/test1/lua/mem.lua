-- Runs one r:* call in a loop and reports how much this child's
-- VmRSS grew, in kB.  /lua/mem.lua?<case>&<iterations>
--
-- Each call should hold on to nothing once it returns, so the growth
-- must not scale with the number of iterations.

local s = string.rep("a/b <c>&d%e\"f", 1260)   -- ~16KB, needs escaping
local b64 = nil
local pct = string.rep("%41", 5461)            -- ~16KB URL-escaped
local pattern = string.rep("a", 4000) .. "(b)" -- a large compiled pattern
local path = string.rep("d", 2000)             -- under PATH_MAX

local cases = {
    noop = function(r) end,

    -- input-sized results
    base64_encode = function(r) r:base64_encode(s) end,
    base64_decode = function(r) r:base64_decode(b64) end,
    escape = function(r) r:escape(s) end,
    unescape = function(r) r:unescape(pct) end,
    escape_html = function(r) r:escape_html(s) end,
    os_escape_path = function(r) r:os_escape_path(s) end,
    escape_logitem = function(r) r:escape_logitem(s) end,
    construct_url = function(r) r:construct_url(s) end,
    runtime_dir_relative = function(r) r:runtime_dir_relative(path) end,
    htpassword = function(r) r:htpassword(s, 1) end, -- ALG_APSHA
    expr = function(r) r:expr("'" .. s .. "' == 'x'") end,
    regex = function(r) r:regex(s, "^(.*)$") end,
    regex_compile = function(r) r:regex("x", pattern) end,
    ivm_get = function(r) r:ivm_get(s) end,
    ivm_set = function(r) r:ivm_set(s, "v") end,

    -- fixed-size results
    md5 = function(r) r:md5("x") end,
    sha1 = function(r) r:sha1("x") end,
    scoreboard_worker = function(r) r:scoreboard_worker(0, 0) end,
    config = function(r) r:config() end,
    options = function(r) local _ = r.options end,
    allowoverrides = function(r) local _ = r.allowoverrides end,
    headers_in = function(r) local _ = r.headers_in end,
    get_direntries = function(r) r:get_direntries(r.document_root) end,
    sendfile = function(r) r:sendfile(r.document_root .. "/lua/empty") end,
    wspeek = function(r) r:wspeek() end,
}

local function rss()
    collectgarbage()
    collectgarbage()
    for line in io.lines("/proc/self/status") do
        local kb = line:match("^VmRSS:%s+(%d+)")
        if kb then return tonumber(kb) end
    end
    return 0
end

function handle(r)
    local name, count = r.args:match("^([%w_]+)&(%d+)$")
    local case = cases[name]
    if not case then return 404 end
    count = tonumber(count)
    b64 = r:base64_encode(string.rep("x", 12288))
    -- One call first, so one-time setup is not counted.
    case(r)
    local before = rss()
    for _ = 1, count do case(r) end
    local after = rss()
    r.content_type = "text/plain"
    r:puts(string.format("%d\n", after - before))
    return apache2.OK
end
