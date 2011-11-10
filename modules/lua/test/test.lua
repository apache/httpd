#!/usr/bin/env lua

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

local mu = require "moonunit" 
local http = require "helpers"

http.base_url = "http://localhost:8008"

local test = mu.TestCase:new{}

function test:document_root()
  local b, c = http.get "/document_root.lua"
  assert(200 == c, "expected status code 200, got " .. c)
  assert(b:find("test"), "test not found in document root")
end

function test:basic_get()
  local b, c = http.get "/basic"
  assert(200 == c, "expected status code 200, got " .. c)
  assert(b:find("hello Lua world"), "'hello Lua world' not found in response")
end

function test:quietly()
  local b, c = http.get "/test_quietly"
  assert(200 == c, "unexpected response code " .. c)
  assert(b == 'hello!', "unexpected response body [" .. b .. "]")
end

function test.basic_post()
  local b, c = http.post "/basic" "hello=7&hello=1"
  assert(200 == c, "expected status code 200, got " .. c)
  assert(b:find("complex:%s+hello: 7, 1\n"), "didn't find complex post parsing")
  assert(b:find("simple:%s+hello: 7\n"), "didn't find simple post parsing")
end

function test.basic_post_alt()
  local b, c = http.post("/test_foo", "hello=7&hello=1")
  assert(201 == c, "expected status code 200, got " .. c)
  assert(b:find("Handler FOO!"), "unexpected output!")
end

function test.post_with_table()
  local b, c = http.post "/basic" { hello = "7" }
  assert(200 == c, "expected status code 200, got " .. c)
  assert(b:find("hello: 7"), "didn't get expected post data [" .. b .."]")
  
  b, c = http.post "/basic" { hello = "7", goodbye = "8" }
  
  assert(200 == c, "expected status code 200, got " .. c)
  assert(b:find("hello: 7"), "didn't get expected post data [" .. b .."]")
  assert(b:find("goodbye: 8"), "didn't get expected post data [" .. b .."]")
end

function test:simple_filter()
  local b, c = http.get "/filter/simple"
  assert(200 == c, "expected status code 200, got " .. c)
end

function test:request_attributes()
  local r, c = http.get "/test_attributes?yes=no"
  assert(201 == c, "expected status code 201, got " .. c)
  
  assert(r:find("status: 200\nstatus: 201"), "changing status code failed")
  assert(r:find("method: GET"), "method wasn't reported correctly")
  assert(r:find("protocol: HTTP/1.1"), "protocol reported incorrectly")
  assert(r:find("assbackwards: false"), "assbackwards reported incorrectly")
  assert(r:find("args: yes=no"), "args not reported correctly")
end

function test:map_regex()
  local r, c = http.get "/test_regex"
  assert(200 == c, "expected status code 200, got " .. c)
  assert(r:find("matched in handle_regex"), "didn't find 'matched in handle_regex'")  
end

function test:map_regex2()
  local r, c = http.get "/test_regex?a=8"
  assert(200 == c, "expected status code 200, got " .. c)
  assert(r:find("matched in handle_regex"), "didn't find 'matched in handle_regex'")  
end

function test:translate_name_hook()
  local r, c = http.get "/translate-name"
  assert(200 == c, "expected 200 got " .. c)
  assert(r:find("please find me"), "didn't get expected static file :-(, instead got " .. r)
end

function test:translate_name_hook2()
  local r, c = http.get "/translate-name2"
  assert(200 == c, "expected 200 got " .. c)
  assert(r:find("please find me"), "didn't get expected static file :-(, instead got " .. r)
end

function test:server_version()
  local r, c = http.get "/test_serverversion"
  assert(200 == c)
  assert(r:find("Apache/2"), "version isn't Apache/2, but is " .. r)
end

function test:fixups_hook()
  local r, c = http.get "/test_fixupstest"
  assert(201 == c, "incorrect status code returned, expected 201 got " .. c)
  assert(r:find("status is 201"), "handler sees incorrect status")
end

function test:simple()
    local r, c = http.get "/simple.lua"
    assert(200 == c, "incorrect status code returned, expected 200 got " .. c)
    assert(r:find("Hi"), "Didn't find 'Hi'")
end

test:run()
