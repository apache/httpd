--[[
    Example output filter that escapes all HTML entities in the output
]]--
function output_filter(r)
    coroutine.yield("prefix\n")
    while bucket do -- For each bucket, do...
        if string.len(bucket) > 0 then
            local output = "bucket:" .. bucket .. "\n"
            coroutine.yield(output) -- Send converted data down the chain
        else
            coroutine.yield("") -- Send converted data down the chain
        end
    end
    coroutine.yield("suffix\n")
    -- No more buckets available.
end
