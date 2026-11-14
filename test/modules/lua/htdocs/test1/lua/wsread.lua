-- The r:wsread() loop from the report.  Some text messages get an
-- answer: "sync" is acknowledged; "rss" is answered with this child's
-- VmRSS in kB, after a full Lua GC so that only memory held outside
-- the Lua heap is left; "peek" with what r:wspeek() returns; and
-- "peekread" by waiting for r:wspeek() and echoing the next message.
function rss()
    collectgarbage()
    for line in io.lines("/proc/self/status") do
        local kb = line:match("^VmRSS:%s+(%d+)")
        if kb then return kb end
    end
    return "0"
end

function handle(r)
    if r:wsupgrade() then
        while true do
            local data = r:wsread()
            if data == nil then break end
            if data == "sync" then r:wswrite("ok") end
            if data == "rss" then r:wswrite(rss()) end
            if data == "peek" then r:wswrite(tostring(r:wspeek())) end
            if data == "peekread" then
                while not r:wspeek() do r.usleep(10000) end
                local next = r:wsread()
                r:wswrite(next)
            end
        end
    end
    return apache2.OK
end
