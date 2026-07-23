-- Syntax: setheader.lua?HeaderName=foo&HeaderValue=bar
-- 
-- This will return a document with 'bar' set in the header 'foo'

function handle(r)
    local GET, GETMULTI = r:parseargs()
    
    r.headers_out[GET['HeaderName']] = GET['HeaderValue']
    r:puts("Header set")
end
