function handle(r)
    r.content_type = "text/plain"
    r:puts("other lua handler\n")
end
