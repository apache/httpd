require 'apache2'

function translate_name(r)
    r:debug("translate_name: " .. r.uri) 
    local query = r:parseargs()
    if query.translateme then
        r:debug("translate_name: translateme  was true " .. r.uri) 
        r.uri = "/modules/lua/hello.lua"
        return apache2.DECLINED
    end
    return apache2.DECLINED
end

function translate_name2(r)
    r:debug("translate_name2: " .. r.uri) 
    local query = r:parseargs()
    if (query.ok) then
        r:debug("will return OK")
    end
    if query.translateme then
        r.uri = "/modules/lua/hello2.lua"
        if query.ok then
	  r.filename= r.document_root .. r.uri
          return apache2.OK
        end
    end
    return apache2.DECLINED
end
