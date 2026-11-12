-- r:sendfile() of a small file, more output after it, then the file
-- again: /lua/sendfile.lua?<count>
function handle(r)
    local path = r.document_root .. "/lua/file.txt"
    r.content_type = "text/plain"
    for _ = 1, tonumber(r.args) do
        r:sendfile(path)
        r:puts("--\n")
    end
    return apache2.OK
end
