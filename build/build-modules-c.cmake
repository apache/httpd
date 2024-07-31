# Licensed to the Apache Software Foundation (ASF) under one or more
# contributor license agreements.  See the NOTICE file distributed with
# this work for additional information regarding copyright ownership.
# The ASF licenses this file to You under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with
# the License.  You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

function(generate_builtin_modules_c output_filename module_list)
  list(PREPEND module_list "core")

  foreach(module ${module_list})
    string(APPEND MODULES_EXTERN "extern module ${module}_module;\n")
    string(APPEND MODULES_PRELINK "  &${module}_module,\n")
    string(APPEND MODULES_SYMBOLS "  {\"${module}_module\", &${module}_module},\n")
    string(APPEND MODULES_PRELOAD "  &${module}_module,\n")
  endforeach()

  configure_file("build/modules.c.in" ${output_filename})
endfunction()
