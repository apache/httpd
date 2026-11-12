-- The r:wsread() loop from the report.  Two text messages get an
-- answer: "sync" is acknowledged, and "rss" is answered with this
-- child's VmRSS in kB, after a full Lua GC so that only memory held
-- outside the Lua heap is left.
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
        end
    end
    return apache2.OK
end
