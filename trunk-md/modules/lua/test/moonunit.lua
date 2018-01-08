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

module("moonunit", package.seeall)

TestCase = {}

function TestCase:new(it)
  it = it or {}
  setmetatable(it, self)
  self.__index = self
  return it
end

function TestCase:run(args)
  args = args or arg
  local function run_test(t, name)
    local status, err = pcall(t, self)
    if status then
      print(("%-39s \27[32mpass\27[39m"):format("[" .. name .. "]"))
    else
      print(("%-39s \27[31mFAIL\27[39m %s"):format("[" .. name .. "]", err))
    end
  end
  
  if (args and #args > 0) then
    for _, v in ipairs(args) do
      if type(self[v]) == "function" then
        run_test(self[v], v)
      else
        print(("%-39s FAIL %s"):format("[" .. v .. "]", 
          "'" .. v .. "' doesn't appear to be a test function"))
      end
    end
  else
    for k, v in pairs(self) do
      run_test(v, k)
    end
  end
end
