function handle(r)
    r.content_type = "text/plain"
    r:puts("Hello Lua World!\n")
end
