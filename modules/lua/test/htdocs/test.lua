-- Licensed to the Apache Software Foundation (ASF) under one or more
-- contributor license agreements.  See the NOTICE file distributed with
-- this work for additional information regarding copyright ownership.
-- The ASF licenses this file to You under the Apache License, Version 2.0
-- (the "License"); you may not use this file except in compliance with
-- the License.  You may obtain a copy of the License at
--
-- http://www.apache.org/licenses/LICENSE-2.0
--
-- Unless required by applicable law or agreed to in writing, software
-- distributed under the License is distributed on an "AS IS" BASIS,
-- WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-- See the License for the specific language governing permissions and
-- limitations under the License.

require 'string'

function print_args(r, simple, complex)
  local s = "    %s: %s\n"
  r:puts("  simple:\n")
  for k, v in pairs(simple) do
    r:puts(s:format(k, v))
  end

  s = "    %s: "
  r:puts("  complex:\n")
  for k, ary in pairs(complex) do
    r:puts(s:format(k))
    for i=1, #ary do
      r:puts(ary[i])
      if i < #ary then r:puts(", ") end
    end
    r:puts("\n")
  end
end

function debug_stuff(r)
  r:debug("This is a debug log message")
  -- r:info("This is an info log message")
  -- r:notice("This is an notice log message")
  -- r:warn("This is an warn log message")
  -- r:err("This is an err log message")
  -- r:alert("This is an alert log message")
  -- r:crit("This is an crit log message")
  -- r:emerg("This is an emerg log message")
end

function handle(r)
  r:puts("hello Lua world\n")
  r:puts("Query args:\n")
  
  print_args(r, r:parseargs());
  
  debug_stuff(r)
    
  r:puts("HTTP Method:\n  " .. r.method .. "\n")

  if r.method == 'POST' then
    print_args(r, r:parsebody())
  end

  require("other")
  r:puts("loaded relative to script:\n  ")
  other.doit(r)
  
  r:puts("loaded from LuaPackagePath:\n")
  require("kangaroo");
  kangaroo.hop(r);
end

function handle_foo(r)
  r:puts("Handler FOO!\n")
  r.status = 201
  r:debug("set status to 201")
end


function handle_attributes(r)
  local function pf(name)
    r:puts(("%s: %s\n"):format(name, tostring(r[name])))
  end

  pf("status")
  r.status = 201
  pf("status")
  r:puts("\n")
    
  pf("content_type")
  r.content_type = "text/plain?charset=ascii"
  pf("content_type")
  r:puts("\n")
  
  pf("method")
  pf("protocol")
  pf("assbackwards")
  pf("the_request")
  pf("range")
  pf("content_encoding")
  pf("user")
  pf("unparsed_uri")
  pf("ap_auth_type")
  pf("uri")
  pf("filename")
  pf("canonical_filename")
  pf("path_info")
  pf("args")
  
  r:puts("\n")
end

function test_headers(r)
  r:puts("test getting and setting headers here\n")
end

function handle_quietly(r)
  r:puts("hello!")
end

function handle_regex(r)
  r:puts("matched in handle_regex")
end

function handle_serverversion(r)
  r:puts(apache2.version)
end

function handle_fixupstest(r)
  r:puts("status is " .. r.status)
end