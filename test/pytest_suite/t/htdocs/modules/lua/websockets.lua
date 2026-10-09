function handle(r)
if r:wsupgrade() then -- if we can upgrade:
    while true do
      local line, isFinal = r:wsread() 
      local len = string.len(line);
      r:debug(string.format("writing line of len %d: %s", len, line))
      if len >= 1024  then
        r:debug("writing line ending in '" .. string.sub(line, -127, -1) .. "'")
      end
      r:wswrite(line)
      if line == "quit" then
        r:wsclose()  -- goodbye!
        break
     end     

    end
end
end
