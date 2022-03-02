function handle(r)
if r:wsupgrade() then -- if we can upgrade:
    while true do
      local line, isFinal = r:wsread()
      r:wswrite(line)
      if line == "quit" then
        r:wsclose()  -- goodbye!
        break
     end

    end
end
end
