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
#
# Read the section on cmake builds in README-FCGID.

PROJECT(mod_fcgid C)

CMAKE_MINIMUM_REQUIRED(VERSION 2.8)

IF(NOT EXISTS ${CMAKE_INSTALL_PREFIX}/lib/libhttpd.lib)
  MESSAGE(FATAL_ERROR "libhttpd.lib was not found in prefix ${CMAKE_INSTALL_PREFIX}")
ENDIF()

# Select APR trunk (libapr-2.lib) if it exists in PREFIX/lib; otherwise, select
# APR 1.x + APR-util 1.x
IF(EXISTS "${CMAKE_INSTALL_PREFIX}/lib/libapr-2.lib")
  SET(apr_libraries
      ${CMAKE_INSTALL_PREFIX}/lib/libapr-2.lib)
ELSEIF(EXISTS "${CMAKE_INSTALL_PREFIX}/lib/libapr-1.lib")
  SET(apr_libraries
      ${CMAKE_INSTALL_PREFIX}/lib/libapr-1.lib
      ${CMAKE_INSTALL_PREFIX}/lib/libaprutil-1.lib)
ELSE()
  MESSAGE(FATAL_ERROR "APR libraries were not found in prefix ${CMAKE_INSTALL_PREFIX}")
ENDIF()

# Misc. options
OPTION(INSTALL_PDB "Install .pdb file (if generated)" ON)

SET(mod_fcgid_sources
    fcgid_bridge.c      fcgid_bucket.c      fcgid_conf.c        fcgid_filter.c
    fcgid_pm_main.c     fcgid_pm_win.c      fcgid_proc_win.c    fcgid_proctbl_win.c
    fcgid_protocol.c    fcgid_spawn_ctl.c   mod_fcgid.c         mod_fcgid.rc
)
INCLUDE_DIRECTORIES(${CMAKE_INSTALL_PREFIX}/include)
ADD_LIBRARY(mod_fcgid SHARED ${mod_fcgid_sources})
# magic base address taken from traditional Windows build
SET_TARGET_PROPERTIES(mod_fcgid PROPERTIES SUFFIX .so LINK_FLAGS /base:0x46430000)
TARGET_LINK_LIBRARIES(mod_fcgid ${CMAKE_INSTALL_PREFIX}/lib/libhttpd.lib ${apr_libraries})
INSTALL(TARGETS mod_fcgid RUNTIME DESTINATION modules)
IF(INSTALL_PDB)
  INSTALL(FILES ${CMAKE_BINARY_DIR}/mod_fcgid.pdb DESTINATION modules
          CONFIGURATIONS RelWithDebInfo Debug)
ENDIF()
