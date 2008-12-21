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

local count = 0

function handle(r)
    r:puts("success in handle " .. count)
end

function handle_server_vm(r)
    r:puts("hello from server scope " .. count)
    count = count + 1
end

function handle_request_vm(r)
    r:puts("hello from request scope " .. count)
    count = count + 1
end

function handle_conn_vm(r)
    r:puts("hello from request scope " .. count)
    count = count + 1
end