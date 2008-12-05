-- require 'string'
-- require 'apache2.config'

function configure(cmd, dir)  
    dir:match_handler {
        pattern = "^/server-says-hi$", 
        file    = "htdocs/config_tests.lua", 
        func    = "handle_server_vm",
        scope   = "server",
        -- options = {
        --     minimum_idle = 10,
        --     maximum_idle = 20
        -- }
    }
    
 
    dir:match_handler {
        pattern = "^/super-basic-config$",
        file    = "htdocs/config_tests.lua"
    }
    --[[
    LuaMapHandler /basic /Users/brianm/src/wombat/test/htdocs/test.lua
    LuaMapHandler /filter/simple /Users/brianm/src/wombat/test/htdocs/filters.lua handle_simple
    LuaMapHandler ^/(\w+)_(\w+)$ /Users/brianm/src/wombat/test/htdocs/$1.lua handle_$2
    ]]--
    
    dir:match_handler {
        pattern = "^/simple$",
        file    = "htdocs/simple.lua"
    }
    
    dir:match_handler {
        pattern = "^/filter/simple$",
        file    = "htdocs/filters.lua",
        func    = "handle_simple"
    }
    
    dir:match_handler {
        pattern = "^/(\\w+)_(\\w+)$",
        file    = "htdocs/$1.lua",
        func    = "handle_$2"
    }
    
    dir:match_handler {
    	pattern = "^/request-says-hi$", 
        file    = "/Users/brianm/src/wombat/test/htdocs/config_tests.lua", 
        func    = "handle_request_vm",
    	scope   = "request"
	}
  
    dir:match_handler {
        pattern = "^/connection-says-hi$", 
     	file    = "/Users/brianm/src/wombat/test/htdocs/test.lua", 
     	func    = "handle_conn_vm",
     	scope   = "connection"
  	}
    
  -- dir:lua_match_handler {
  --   pattern = "^/once-says-hi$", 
  --   file    = "/Users/brianm/src/wombat/test/htdocs/test.lua", 
  --   func    = "handle_configure_server",
  --   scope   = "tests"
  -- }
end
