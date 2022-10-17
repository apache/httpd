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
# Read README.cmake before using this.

PROJECT(HTTPD C)

CMAKE_MINIMUM_REQUIRED(VERSION 2.8)

INCLUDE(CheckSymbolExists)
INCLUDE(CheckCSourceCompiles)

FIND_PACKAGE(LibXml2)
FIND_PACKAGE(Lua51)
FIND_PACKAGE(OpenSSL)
FIND_PACKAGE(ZLIB)
FIND_PACKAGE(CURL)

# Options for support libraries not supported by cmake-bundled FindFOO

# Default to using APR trunk (libapr-2.lib) if it exists in PREFIX/lib;
# otherwise, default to APR 1.x + APR-util 1.x
IF(EXISTS "${CMAKE_INSTALL_PREFIX}/lib/libapr-2.lib")
  SET(default_apr_libraries "${CMAKE_INSTALL_PREFIX}/lib/libapr-2.lib")
ELSEIF(EXISTS "${CMAKE_INSTALL_PREFIX}/lib/libapr-1.lib")
  SET(ldaplib "${CMAKE_INSTALL_PREFIX}/lib/apr_ldap-1.lib")
  IF(NOT EXISTS ${ldaplib})
    SET(ldaplib)
  ENDIF()
  SET(default_apr_libraries ${CMAKE_INSTALL_PREFIX}/lib/libapr-1.lib ${CMAKE_INSTALL_PREFIX}/lib/libaprutil-1.lib ${ldaplib})
ELSE()
  SET(default_apr_libraries)
ENDIF()

# PCRE names its libraries differently for debug vs. release builds.
# We can't query our own CMAKE_BUILD_TYPE at configure time.
# If the debug version exists in PREFIX/lib, default to that one.
IF(EXISTS "${CMAKE_INSTALL_PREFIX}/lib/pcre2-8d.lib")
  SET(default_pcre_libraries ${CMAKE_INSTALL_PREFIX}/lib/pcre2-8d.lib)
  SET(default_pcre_cflags "-DHAVE_PCRE2")
ELSEIF(EXISTS "${CMAKE_INSTALL_PREFIX}/lib/pcre2-8.lib")
  SET(default_pcre_libraries ${CMAKE_INSTALL_PREFIX}/lib/pcre2-8.lib)
  SET(default_pcre_cflags "-DHAVE_PCRE2")
ELSEIF(EXISTS "${CMAKE_INSTALL_PREFIX}/lib/pcred.lib")
  SET(default_pcre_libraries ${CMAKE_INSTALL_PREFIX}/lib/pcred.lib)
ELSE()
  SET(default_pcre_libraries ${CMAKE_INSTALL_PREFIX}/lib/pcre.lib)
ENDIF()

IF(EXISTS "${CMAKE_INSTALL_PREFIX}/lib/nghttp2d.lib")
  SET(default_nghttp2_libraries "${CMAKE_INSTALL_PREFIX}/lib/nghttp2d.lib")
ELSE()
  SET(default_nghttp2_libraries "${CMAKE_INSTALL_PREFIX}/lib/nghttp2.lib")
ENDIF()

IF(EXISTS "${CMAKE_INSTALL_PREFIX}/lib/brotlienc.lib")
  SET(default_brotli_libraries "${CMAKE_INSTALL_PREFIX}/lib/brotlienc.lib" "${CMAKE_INSTALL_PREFIX}/lib/brotlicommon.lib")
ELSE()
  SET(default_brotli_libraries)
ENDIF()

IF(EXISTS "${CMAKE_INSTALL_PREFIX}/lib/jansson.lib")
  SET(default_jansson_libraries "${CMAKE_INSTALL_PREFIX}/lib/jansson.lib")
ELSE()
  SET(default_jansson_libraries)
ENDIF()

SET(APR_INCLUDE_DIR       "${CMAKE_INSTALL_PREFIX}/include" CACHE STRING "Directory with APR[-Util] include files")
SET(APR_LIBRARIES         ${default_apr_libraries}       CACHE STRING "APR libraries to link with")
SET(NGHTTP2_INCLUDE_DIR   "${CMAKE_INSTALL_PREFIX}/include" CACHE STRING "Directory with NGHTTP2 include files within nghttp2 subdirectory")
SET(NGHTTP2_LIBRARIES     ${default_nghttp2_libraries}   CACHE STRING "NGHTTP2 libraries to link with")
SET(PCRE_CFLAGS           "${default_pcre_cflags}"       CACHE STRING "PCRE flags for util_pcre.c compilation")
SET(PCRE_INCLUDE_DIR      "${CMAKE_INSTALL_PREFIX}/include" CACHE STRING "Directory with PCRE include files")
SET(PCRE_LIBRARIES        ${default_pcre_libraries}      CACHE STRING "PCRE libraries to link with")
SET(LIBXML2_ICONV_INCLUDE_DIR     ""                     CACHE STRING "Directory with iconv include files for libxml2")
SET(LIBXML2_ICONV_LIBRARIES       ""                     CACHE STRING "iconv libraries to link with for libxml2")
SET(BROTLI_INCLUDE_DIR    "${CMAKE_INSTALL_PREFIX}/include" CACHE STRING "Directory with include files for Brotli")
SET(BROTLI_LIBRARIES      ${default_brotli_libraries}    CACHE STRING "Brotli libraries to link with")
SET(JANSSON_INCLUDE_DIR   "${CMAKE_INSTALL_PREFIX}/include" CACHE STRING "Directory with include files for jansson")
SET(JANSSON_LIBRARIES     "${default_jansson_libraries}" CACHE STRING "Jansson libraries to link with")
# end support library configuration

# Misc. options
OPTION(INSTALL_PDB        "Install .pdb files (if generated)"  ON)
OPTION(INSTALL_MANUAL     "Install manual"                     ON)

SET(ENABLE_MODULES        "O"                            CACHE STRING "Minimum module enablement (e.g., \"i\" to build all but those without prerequisites)")
SET(WITH_MODULES          ""                             CACHE STRING "comma-separated paths to single-file modules to statically link into the server")
SET(EXTRA_INCLUDES        ""                             CACHE STRING "Extra include directories")
SET(EXTRA_LIBS            ""                             CACHE STRING "Extra libraries")
SET(EXTRA_COMPILE_FLAGS   ""                             CACHE STRING "Extra compile flags")

IF(NOT EXISTS "${APR_INCLUDE_DIR}/apr.h")
  MESSAGE(FATAL_ERROR "APR include directory ${APR_INCLUDE_DIR} is not correct.")
ENDIF()
FOREACH(onelib ${APR_LIBRARIES})
  IF(NOT EXISTS ${onelib})
    MESSAGE(FATAL_ERROR "APR library ${onelib} was not found.")
  ENDIF()
ENDFOREACH()

MACRO(DEFINE_WITH_BLANKS output_definition input_symbol input_value)
  IF(MSVC_IDE OR ${CMAKE_MAJOR_VERSION}.${CMAKE_MINOR_VERSION}.${CMAKE_PATCH_VERSION} VERSION_GREATER 2.8.11)
    SET(${output_definition} "-D${input_symbol}=\"${input_value}\"")
  ELSE()
    # command-line tool + older cmake, where extra quotes must be added and
    # escaped to survive
    SET(${output_definition} "-D${input_symbol}=\"\\\"${input_value}\\\"\"")
  ENDIF()
ENDMACRO()

MACRO(GET_MOD_ENABLE_RANK macro_modname macro_mod_enable_val macro_output_rank)
  IF(${macro_mod_enable_val} STREQUAL "O")
    SET(${macro_output_rank} 0)
  ELSEIF(${macro_mod_enable_val} STREQUAL "i")
    SET(${macro_output_rank} 1)
  ELSEIF(${macro_mod_enable_val} STREQUAL "I")
    SET(${macro_output_rank} 2)
  ELSEIF(${macro_mod_enable_val} STREQUAL "a")
    SET(${macro_output_rank} 3)
  ELSEIF(${macro_mod_enable_val} STREQUAL "A")
    SET(${macro_output_rank} 4)
  ELSE()
    MESSAGE(FATAL_ERROR "Unexpected enablement value \"${macro_mod_enable_val}\" for ${macro_modname}")
  ENDIF()
ENDMACRO()

GET_MOD_ENABLE_RANK("ENABLE_MODULES setting" ${ENABLE_MODULES} enable_modules_rank)

# Figure out what APR/APU features are available
#
# CHECK_APR_FEATURE checks for features defined to 1 or 0 in apr.h or apu.h
# The symbol representing the feature will be set to TRUE or FALSE for 
# compatibility with the feature tests set by FindFooPackage.
#
# (unclear why CHECK_SYMBOL_EXISTS is needed, but I was getting "found" for anything 
# not defined to either 1 or 0)

MACRO(CHECK_APR_FEATURE which_define)
  SET(CMAKE_REQUIRED_INCLUDES "${APR_INCLUDE_DIR}")
  CHECK_SYMBOL_EXISTS(${which_define} "apr.h;apu.h" tmp_${which_define})
  IF(${tmp_${which_define}})
    CHECK_C_SOURCE_COMPILES("#include \"${APR_INCLUDE_DIR}/apr.h\"
      #include \"${APR_INCLUDE_DIR}/apu.h\"
      int main() {
      #ifndef ${which_define}
      #error gobble
      #endif
      #if !${which_define}
      #error gobble
      #endif
      return 1;}" ${which_define})
  ELSE()
    SET(${which_define})
  ENDIF()
  IF(${${which_define}})
    SET(${which_define} TRUE)
  ELSE()
    SET(${which_define} FALSE)
  ENDIF()
ENDMACRO()

CHECK_APR_FEATURE(APR_HAS_XLATE)
CHECK_APR_FEATURE(APU_HAVE_CRYPTO)

# APR_HAS_LDAP is defined in apr_ldap.h, which exists only in apr 1.x, so use
# special code instead of CHECK_APR_FEATURE()
# As with CHECK_APR_FEATURE(), convert to a TRUE/FALSE result.
CHECK_C_SOURCE_COMPILES("#include \"${APR_INCLUDE_DIR}/apr.h\"
#include \"${APR_INCLUDE_DIR}/apr_ldap.h\"
int main() {
#if !APR_HAS_LDAP
#error gobble
#endif
return 1;}" APR_HAS_LDAP)
IF(${APR_HAS_LDAP})
  SET(APR_HAS_LDAP TRUE)
ELSE()
  SET(APR_HAS_LDAP FALSE)
ENDIF()

# See if nghttp2 exists in a configured or defaulted location
SET(NGHTTP2_FOUND TRUE)
IF(EXISTS "${NGHTTP2_INCLUDE_DIR}/nghttp2/nghttp2.h")
  FOREACH(onelib ${NGHTTP2_LIBRARIES})
    IF(NOT EXISTS ${onelib})
      SET(NGHTTP2_FOUND FALSE)
    ENDIF()
  ENDFOREACH()
ELSE()
  SET(NGHTTP2_FOUND FALSE)
ENDIF()

# See if we have Brotli
SET(BROTLI_FOUND TRUE)
IF(EXISTS "${BROTLI_INCLUDE_DIR}/brotli/encode.h")
  FOREACH(onelib ${BROTLI_LIBRARIES})
    IF(NOT EXISTS ${onelib})
      SET(BROTLI_FOUND FALSE)
    ENDIF()
  ENDFOREACH()
ELSE()
  SET(BROTLI_FOUND FALSE)
ENDIF()

# See if we have Jansson
SET(JANSSON_FOUND TRUE)
IF(EXISTS "${JANSSON_INCLUDE_DIR}/jansson.h")
  FOREACH(onelib ${JANSSON_LIBRARIES})
    IF(NOT EXISTS ${onelib})
      SET(JANSSON_FOUND FALSE)
    ENDIF()
  ENDFOREACH()
ELSE()
  SET(JANSSON_FOUND FALSE)
ENDIF()


MESSAGE(STATUS "")
MESSAGE(STATUS "Summary of feature detection:")
MESSAGE(STATUS "")
MESSAGE(STATUS "LIBXML2_FOUND ............ : ${LIBXML2_FOUND}")
MESSAGE(STATUS "LUA51_FOUND .............. : ${LUA51_FOUND}")
MESSAGE(STATUS "NGHTTP2_FOUND ............ : ${NGHTTP2_FOUND}")
MESSAGE(STATUS "OPENSSL_FOUND ............ : ${OPENSSL_FOUND}")
MESSAGE(STATUS "ZLIB_FOUND ............... : ${ZLIB_FOUND}")
MESSAGE(STATUS "BROTLI_FOUND ............. : ${BROTLI_FOUND}")
MESSAGE(STATUS "CURL_FOUND ............... : ${CURL_FOUND}")
MESSAGE(STATUS "JANSSON_FOUND ............ : ${JANSSON_FOUND}")
MESSAGE(STATUS "APR_HAS_LDAP ............. : ${APR_HAS_LDAP}")
MESSAGE(STATUS "APR_HAS_XLATE ............ : ${APR_HAS_XLATE}")
MESSAGE(STATUS "APU_HAVE_CRYPTO .......... : ${APU_HAVE_CRYPTO}")
MESSAGE(STATUS "")

# Options for each available module
#   "A" ("A"ctive) means installed and active in default .conf, fail if can't be built
#   "I" ("I"nactive) means installed and inactive (LoadModule commented out) in default .conf, fail if can't be built
#   "O" ("O"mit) means not installed, no LoadModule
#   "a" - like "A", but ignore with a warning if any prereqs aren't available
#   "i" - like "I", but ignore with a warning if any prereqs aren't available

# Current heuristic for default enablement:
#
#   Module requires a prereq and           -> O
#   finding/usingprereq isn't implemented
#   yet
#
#   Module is included by default in       -> a if it has prereqs, A otherwise
#   autoconf-based build 
#
#   Module is included in                  -> i if it has prereqs, I otherwise
#   --enable-modules=most 
#
#   Otherwise                              -> O
#
SET(MODULE_LIST
  "modules/aaa/mod_access_compat+A+mod_access compatibility"
  "modules/aaa/mod_allowmethods+I+restrict allowed HTTP methods"
  "modules/aaa/mod_auth_basic+A+basic authentication"
  "modules/aaa/mod_auth_digest+I+RFC2617 Digest authentication"
  "modules/aaa/mod_auth_form+I+form authentication"
  "modules/aaa/mod_authn_anon+I+anonymous user authentication control"
  "modules/aaa/mod_authn_core+A+core authentication module"
  "modules/aaa/mod_authn_dbd+I+SQL-based authentication control"
  "modules/aaa/mod_authn_dbm+I+DBM-based authentication control"
  "modules/aaa/mod_authn_file+A+file-based authentication control"
  "modules/aaa/mod_authn_socache+I+Cached authentication control"
  "modules/aaa/mod_authnz_fcgi+I+FastCGI authorizer-based authentication and authorization"
  "modules/aaa/mod_authnz_ldap+i+LDAP based authentication"
  "modules/aaa/mod_authz_core+A+core authorization provider vector module"
  "modules/aaa/mod_authz_dbd+I+SQL based authorization and Login/Session support"
  "modules/aaa/mod_authz_dbm+I+DBM-based authorization control"
  "modules/aaa/mod_authz_groupfile+A+'require group' authorization control"
  "modules/aaa/mod_authz_host+A+host-based authorization control"
  "modules/aaa/mod_authz_owner+I+'require file-owner' authorization control"
  "modules/aaa/mod_authz_user+A+'require user' authorization control"
  "modules/arch/win32/mod_isapi+I+isapi extension support"
  "modules/cache/mod_cache+I+dynamic file caching.  At least one storage management module (e.g. mod_cache_disk) is also necessary."
  "modules/cache/mod_cache_disk+I+disk caching module"
  "modules/cache/mod_cache_socache+I+shared object caching module"
  "modules/cache/mod_file_cache+I+File cache"
  "modules/cache/mod_socache_dbm+I+dbm small object cache provider"
  "modules/cache/mod_socache_dc+O+distcache small object cache provider"
  "modules/cache/mod_socache_memcache+I+memcache small object cache provider"
  "modules/cache/mod_socache_shmcb+I+ shmcb small object cache provider"
  "modules/cache/mod_socache_redis+I+redis small object cache provider"
  "modules/cluster/mod_heartbeat+I+Generates Heartbeats"
  "modules/cluster/mod_heartmonitor+I+Collects Heartbeats"
  "modules/core/mod_macro+I+Define and use macros in configuration files"
  "modules/core/mod_watchdog+I+Watchdog module"
  "modules/database/mod_dbd+I+Apache DBD Framework"
  "modules/dav/fs/mod_dav_fs+I+DAV provider for the filesystem."
  "modules/dav/lock/mod_dav_lock+I+DAV provider for generic locking"
  "modules/dav/main/mod_dav+I+WebDAV protocol handling."
  "modules/debugging/mod_bucketeer+O+buckets manipulation filter.  Useful only for developers and testing purposes."
  "modules/debugging/mod_dumpio+I+I/O dump filter"
  "modules/echo/mod_echo+O+ECHO server"
  "modules/examples/mod_case_filter+O+Example uppercase conversion filter"
  "modules/examples/mod_case_filter_in+O+Example uppercase conversion input filter"
  "modules/examples/mod_example_hooks+O+Example hook callback handler module"
  "modules/examples/mod_example_ipc+O+Example of shared memory and mutex usage"
  "modules/filters/mod_brotli+i+Brotli compression support"
  "modules/filters/mod_buffer+I+Filter Buffering"
  "modules/filters/mod_charset_lite+i+character set translation"
  "modules/filters/mod_data+O+RFC2397 data encoder"
  "modules/filters/mod_deflate+i+Deflate transfer encoding support"
  "modules/filters/mod_ext_filter+I+external filter module"
  "modules/filters/mod_filter+A+Smart Filtering"
  "modules/filters/mod_include+I+Server Side Includes"
  "modules/filters/mod_proxy_html+i+Fix HTML Links in a Reverse Proxy"
  "modules/filters/mod_ratelimit+I+Output Bandwidth Limiting"
  "modules/filters/mod_reflector+O+Reflect request through the output filter stack"
  "modules/filters/mod_reqtimeout+A+Limit time waiting for request from client"
  "modules/filters/mod_request+I+Request Body Filtering"
  "modules/filters/mod_sed+I+filter request and/or response bodies through sed"
  "modules/filters/mod_substitute+I+response content rewrite-like filtering"
  "modules/filters/mod_xml2enc+i+i18n support for markup filters"
  "modules/generators/mod_asis+I+as-is filetypes"
  "modules/generators/mod_autoindex+A+directory listing"
  "modules/generators/mod_cgi+I+CGI scripts"
  "modules/generators/mod_info+I+server information"
  "modules/generators/mod_status+I+process/thread monitoring"
  "modules/http/mod_mime+A+mapping of file-extension to MIME.  Disabling this module is normally not recommended."
  "modules/http2/mod_http2+i+HTTP/2 protocol support"
  "modules/ldap/mod_ldap+i+LDAP caching and connection pooling services"
  "modules/loggers/mod_log_config+A+logging configuration.  You won't be able to log requests to the server without this module."
  "modules/loggers/mod_log_debug+I+configurable debug logging"
  "modules/loggers/mod_log_forensic+I+forensic logging"
  "modules/loggers/mod_logio+I+input and output logging"
  "modules/lua/mod_lua+i+Apache Lua Framework"
  "modules/md/mod_md+i+Apache Managed Domains (Certificates)"
  "modules/mappers/mod_actions+I+Action triggering on requests"
  "modules/mappers/mod_alias+A+mapping of requests to different filesystem parts"
  "modules/mappers/mod_dir+A+directory request handling"
  "modules/mappers/mod_imagemap+I+server-side imagemaps"
  "modules/mappers/mod_negotiation+I+content negotiation"
  "modules/mappers/mod_rewrite+I+rule based URL manipulation"
  "modules/mappers/mod_speling+I+correct common URL misspellings"
  "modules/mappers/mod_userdir+I+mapping of requests to user-specific directories"
  "modules/mappers/mod_vhost_alias+I+mass virtual hosting module"
  "modules/metadata/mod_cern_meta+O+CERN-type meta files"
  "modules/metadata/mod_env+A+clearing/setting of ENV vars"
  "modules/metadata/mod_expires+I+Expires header control"
  "modules/metadata/mod_headers+A+HTTP header control"
  "modules/metadata/mod_ident+O+RFC 1413 identity check"
  "modules/metadata/mod_mime_magic+O+automagically determining MIME type"
  "modules/metadata/mod_remoteip+I+translate header contents to an apparent client remote_ip"
  "modules/metadata/mod_setenvif+A+basing ENV vars on headers"
  "modules/metadata/mod_unique_id+I+per-request unique ids"
  "modules/metadata/mod_usertrack+I+user-session tracking"
  "modules/metadata/mod_version+A+determining httpd version in config files"
  "modules/proxy/balancers/mod_lbmethod_bybusyness+I+Apache proxy Load balancing by busyness"
  "modules/proxy/balancers/mod_lbmethod_byrequests+I+Apache proxy Load balancing by request counting"
  "modules/proxy/balancers/mod_lbmethod_bytraffic+I+Apache proxy Load balancing by traffic counting"
  "modules/proxy/balancers/mod_lbmethod_heartbeat+I+Apache proxy Load balancing from Heartbeats"
  "modules/proxy/mod_proxy_ajp+I+Apache proxy AJP module.  Requires and is enabled by --enable-proxy."
  "modules/proxy/mod_proxy_balancer+I+Apache proxy BALANCER module.  Requires and is enabled by --enable-proxy."
  "modules/proxy/mod_proxy+I+Apache proxy module"
  "modules/proxy/mod_proxy_connect+I+Apache proxy CONNECT module.  Requires and is enabled by --enable-proxy."
  "modules/proxy/mod_proxy_express+I+mass reverse-proxy module. Requires --enable-proxy."
  "modules/proxy/mod_proxy_fcgi+I+Apache proxy FastCGI module.  Requires and is enabled by --enable-proxy."
  "modules/proxy/mod_proxy_ftp+I+Apache proxy FTP module.  Requires and is enabled by --enable-proxy."
  "modules/proxy/mod_proxy_http+I+Apache proxy HTTP module.  Requires and is enabled by --enable-proxy."
  "modules/proxy/mod_proxy_hcheck+I+Apache proxy health check module.  Requires and is enabled by --enable-proxy."
  "modules/proxy/mod_proxy_scgi+I+Apache proxy SCGI module.  Requires and is enabled by --enable-proxy."
  "modules/proxy/mod_proxy_wstunnel+I+Apache proxy Websocket Tunnel module.  Requires and is enabled by --enable-proxy."
  "modules/http2/mod_proxy_http2+i+Apache proxy HTTP/2 module.  Requires --enable-proxy."
  "modules/session/mod_session+I+session module"
  "modules/session/mod_session_cookie+I+session cookie module"
  "modules/session/mod_session_crypto+i+session crypto module"
  "modules/session/mod_session_dbd+I+session dbd module"
  "modules/slotmem/mod_slotmem_plain+I+slotmem provider that uses plain memory"
  "modules/slotmem/mod_slotmem_shm+I+slotmem provider that uses shared memory"
  "modules/ssl/mod_ssl+i+SSL/TLS support"
  "modules/test/mod_dialup+O+rate limits static files to dialup modem speeds"
  "modules/test/mod_optional_fn_export+O+example optional function exporter"
  "modules/test/mod_optional_fn_import+O+example optional function importer"
  "modules/test/mod_optional_hook_export+O+example optional hook exporter"
  "modules/test/mod_optional_hook_import+O+example optional hook importer"
)

# Track which modules actually built have APIs to link against.
SET(installed_mod_libs_exps)

# Define extra definitions, sources, headers, etc. required by some modules.
# This could be included in the master list of modules above, though it 
# certainly would get a lot more unreadable.
SET(mod_apreq_extra_defines          APREQ_DECLARE_EXPORT)
SET(mod_apreq_extra_sources          modules/apreq/handle.c)
SET(mod_apreq_main_source            modules/apreq/filter.c)
SET(mod_authz_dbd_extra_defines      AUTHZ_DBD_DECLARE_EXPORT)
SET(mod_authnz_ldap_requires         APR_HAS_LDAP)
SET(mod_authnz_ldap_extra_libs       mod_ldap)
SET(mod_cache_extra_defines          CACHE_DECLARE_EXPORT)
SET(mod_cache_extra_sources
  modules/cache/cache_storage.c      modules/cache/cache_util.c
)
SET(mod_cache_install_lib 1)
SET(mod_cache_disk_extra_libs        mod_cache)
SET(mod_cache_socache_extra_libs     mod_cache)
SET(mod_charset_lite_requires        APR_HAS_XLATE)
SET(mod_dav_extra_defines            DAV_DECLARE_EXPORT)
SET(mod_dav_extra_sources
  modules/dav/main/liveprop.c        modules/dav/main/props.c
  modules/dav/main/std_liveprop.c    modules/dav/main/providers.c
  modules/dav/main/util.c            modules/dav/main/util_lock.c
)
SET(mod_dav_install_lib 1)
SET(mod_dav_fs_extra_sources
  modules/dav/fs/dbm.c               modules/dav/fs/lock.c
  modules/dav/fs/repos.c
)
SET(mod_dav_fs_extra_libs            mod_dav)
SET(mod_dav_lock_extra_sources       modules/dav/lock/locks.c)
SET(mod_dav_lock_extra_libs          mod_dav)
SET(mod_dbd_extra_defines            DBD_DECLARE_EXPORT)
SET(mod_deflate_requires             ZLIB_FOUND)
IF(ZLIB_FOUND)
  SET(mod_deflate_extra_includes       ${ZLIB_INCLUDE_DIR})
  SET(mod_deflate_extra_libs           ${ZLIB_LIBRARIES})
ENDIF()
SET(mod_brotli_requires              BROTLI_FOUND)
IF(BROTLI_FOUND)
  SET(mod_brotli_extra_includes        ${BROTLI_INCLUDE_DIR})
  SET(mod_brotli_extra_libs            ${BROTLI_LIBRARIES})
ENDIF()
SET(mod_firehose_requires            SOMEONE_TO_MAKE_IT_COMPILE_ON_WINDOWS)
SET(mod_heartbeat_extra_libs         mod_watchdog)
SET(mod_http2_requires               NGHTTP2_FOUND)
SET(mod_http2_extra_defines          ssize_t=long)
SET(mod_http2_extra_includes         ${NGHTTP2_INCLUDE_DIR})
SET(mod_http2_extra_libs             ${NGHTTP2_LIBRARIES})
SET(mod_http2_extra_sources
   modules/http2/h2_bucket_beam.c     modules/http2/h2_bucket_eos.c
   modules/http2/h2_c1.c              modules/http2/h2_c1_io.c
   modules/http2/h2_c2.c              modules/http2/h2_c2_filter.c
   modules/http2/h2_config.c          modules/http2/h2_conn_ctx.c
   modules/http2/h2_mplx.c            modules/http2/h2_headers.c
   modules/http2/h2_protocol.c        modules/http2/h2_push.c
   modules/http2/h2_request.c         modules/http2/h2_session.c
   modules/http2/h2_stream.c          modules/http2/h2_switch.c
   modules/http2/h2_util.c            modules/http2/h2_workers.c
)
SET(mod_ldap_extra_defines           LDAP_DECLARE_EXPORT)
SET(mod_ldap_extra_libs              wldap32)
SET(mod_ldap_extra_sources
  modules/ldap/util_ldap_cache.c     modules/ldap/util_ldap_cache_mgr.c
)
SET(mod_ldap_main_source             modules/ldap/util_ldap.c)
SET(mod_ldap_requires                APR_HAS_LDAP)
SET(mod_lua_extra_defines            AP_LUA_DECLARE_EXPORT)
SET(mod_lua_extra_includes           ${LUA_INCLUDE_DIR})
SET(mod_lua_extra_libs               ${LUA_LIBRARIES})
SET(mod_lua_extra_sources
  modules/lua/lua_apr.c              modules/lua/lua_config.c
  modules/lua/lua_passwd.c           modules/lua/lua_request.c
  modules/lua/lua_vmprep.c           modules/lua/lua_dbd.c
)
SET(mod_lua_requires                 LUA51_FOUND)
SET(mod_md_requires                  OPENSSL_FOUND CURL_FOUND JANSSON_FOUND)
SET(mod_md_extra_includes            ${OPENSSL_INCLUDE_DIR} ${CURL_INCLUDE_DIR} ${JANSSON_INCLUDE_DIR})
SET(mod_md_extra_libs                ${OPENSSL_LIBRARIES} ${CURL_LIBRARIES} ${JANSSON_LIBRARIES} mod_watchdog)
SET(mod_md_extra_sources
  modules/md/md_acme.c               modules/md/md_acme_acct.c
  modules/md/md_acme_authz.c         modules/md/md_acme_drive.c
  modules/md/md_acmev2_drive.c       modules/md/md_event.c
  modules/md/md_acme_order.c         modules/md/md_core.c
  modules/md/md_curl.c               modules/md/md_crypt.c
  modules/md/md_http.c               modules/md/md_json.c
  modules/md/md_jws.c                modules/md/md_log.c
  modules/md/md_result.c             modules/md/md_reg.c
  modules/md/md_status.c             modules/md/md_store.c
  modules/md/md_store_fs.c           modules/md/md_time.c
  modules/md/md_ocsp.c               modules/md/md_util.c               
  modules/md/mod_md_config.c         modules/md/mod_md_drive.c
  modules/md/mod_md_os.c             modules/md/mod_md_status.c
  modules/md/mod_md_ocsp.c           modules/md/md_tailscale.c
)
SET(mod_optional_hook_export_extra_defines AP_DECLARE_EXPORT) # bogus reuse of core API prefix
SET(mod_proxy_extra_defines          PROXY_DECLARE_EXPORT)
SET(mod_proxy_extra_sources          modules/proxy/proxy_util.c)
SET(mod_proxy_install_lib 1)
SET(mod_proxy_ajp_extra_sources
  modules/proxy/ajp_header.c         modules/proxy/ajp_link.c
  modules/proxy/ajp_msg.c            modules/proxy/ajp_utils.c
)
SET(mod_proxy_ajp_extra_libs         mod_proxy)
SET(mod_proxy_balancer_extra_libs    mod_proxy)
SET(mod_proxy_connect_extra_libs     mod_proxy)
SET(mod_proxy_express_extra_libs     mod_proxy)
SET(mod_proxy_fcgi_extra_libs        mod_proxy)
SET(mod_proxy_ftp_extra_libs         mod_proxy)
SET(mod_proxy_hcheck_extra_libs      mod_proxy)
SET(mod_proxy_http_extra_libs        mod_proxy)
SET(mod_proxy_html_requires          LIBXML2_FOUND)
IF(LIBXML2_FOUND)
  SET(mod_proxy_html_extra_includes    "${LIBXML2_INCLUDE_DIR};${LIBXML2_ICONV_INCLUDE_DIR}")
  SET(mod_proxy_html_extra_libs        "${LIBXML2_LIBRARIES};${LIBXML2_ICONV_LIBRARIES}")
ENDIF()
SET(mod_proxy_scgi_extra_libs        mod_proxy)
SET(mod_proxy_wstunnel_extra_libs    mod_proxy)
SET(mod_proxy_http2_requires               NGHTTP2_FOUND)
SET(mod_proxy_http2_extra_defines          ssize_t=long)
SET(mod_proxy_http2_extra_includes         ${NGHTTP2_INCLUDE_DIR})
SET(mod_proxy_http2_extra_libs             ${NGHTTP2_LIBRARIES} mod_proxy)
SET(mod_proxy_http2_extra_sources
  modules/http2/h2_proxy_session.c   modules/http2/h2_proxy_util.c
)
SET(mod_ratelimit_extra_defines      AP_RL_DECLARE_EXPORT)
SET(mod_sed_extra_sources
  modules/filters/regexp.c           modules/filters/sed0.c
  modules/filters/sed1.c
)
SET(mod_serf_requires                AN_UNIMPLEMENTED_SUPPORT_LIBRARY_REQUIREMENT)
SET(mod_session_extra_defines        SESSION_DECLARE_EXPORT)
SET(mod_session_install_lib 1)
SET(mod_session_cookie_extra_libs    mod_session)
SET(mod_session_crypto_requires      APU_HAVE_CRYPTO)
SET(mod_session_crypto_extra_libs    mod_session)
SET(mod_session_dbd_extra_libs       mod_session)
SET(mod_socache_dc_requires          AN_UNIMPLEMENTED_SUPPORT_LIBRARY_REQUIREMENT)
SET(mod_ssl_extra_defines            SSL_DECLARE_EXPORT)
SET(mod_ssl_requires                 OPENSSL_FOUND)
IF(OPENSSL_FOUND)
  SET(mod_ssl_extra_includes           ${OPENSSL_INCLUDE_DIR})
  SET(mod_ssl_extra_libs               ${OPENSSL_LIBRARIES})
ENDIF()
SET(mod_ssl_extra_sources
  modules/ssl/ssl_engine_config.c
  modules/ssl/ssl_engine_init.c      modules/ssl/ssl_engine_io.c
  modules/ssl/ssl_engine_kernel.c    modules/ssl/ssl_engine_log.c
  modules/ssl/ssl_engine_mutex.c     modules/ssl/ssl_engine_ocsp.c
  modules/ssl/ssl_engine_pphrase.c   modules/ssl/ssl_engine_rand.c
  modules/ssl/ssl_engine_vars.c      modules/ssl/ssl_scache.c
  modules/ssl/ssl_util.c             modules/ssl/ssl_util_ocsp.c
  modules/ssl/ssl_util_ssl.c         modules/ssl/ssl_util_stapling.c
)
SET(mod_status_extra_defines         STATUS_DECLARE_EXPORT)
SET(mod_watchdog_install_lib 1)
SET(mod_xml2enc_requires             LIBXML2_FOUND)
IF(LIBXML2_FOUND)
  SET(mod_xml2enc_extra_includes     "${LIBXML2_INCLUDE_DIR};${LIBXML2_ICONV_INCLUDE_DIR}")
  SET(mod_xml2enc_extra_libs         "${LIBXML2_LIBRARIES};${LIBXML2_ICONV_LIBRARIES}")
ENDIF()
SET(mod_watchdog_extra_defines       AP_WD_DECLARE_EXPORT)

SET(MODULE_PATHS)
FOREACH (modinfo ${MODULE_LIST})
  STRING(REGEX REPLACE "([^+]*)\\+([^+]*)\\+([^+]*)" "\\1;\\2;\\3" modinfolist ${modinfo})
  SET(path_to_module)
  SET(defaultenable)
  SET(helptext)
  FOREACH(i ${modinfolist})
    IF("${path_to_module}" STREQUAL "")
      SET(path_to_module ${i})
    ELSEIF("${defaultenable}" STREQUAL "")
      SET(defaultenable ${i})
    ELSEIF("${helptext}" STREQUAL "")
      SET(helptext ${i})
    ELSE()
      MESSAGE(FATAL_ERROR "Unexpected field or plus sign in >${modinfo}<")
    ENDIF()
  ENDFOREACH()

  # MESSAGE("       path to module: ${path_to_module}")
  # MESSAGE("enablement by default: ${defaultenable}")
  # MESSAGE("            help text: ${helptext}")

  STRING(REGEX REPLACE ".*/(mod_[^\\+]+)" "\\1" mod_name       ${path_to_module})
  STRING(REGEX REPLACE "mod_(.*)"         "\\1" mod_shortname  ${mod_name})

  STRING(TOUPPER "ENABLE_${mod_shortname}" mod_option_name)

  SET(${mod_option_name} ${defaultenable} CACHE STRING ${helptext})
  SET(MODULE_PATHS "${MODULE_PATHS};${path_to_module}")

ENDFOREACH()

SET(install_targets)
SET(install_bin_pdb)
SET(install_modules) # special handling vs. other installed targets
SET(install_modules_pdb)
SET(builtin_module_shortnames "win32 mpm_winnt http so") # core added automatically
SET(extra_builtin_modules) # the ones specified with -DWITH_MODULES=

IF(WITH_MODULES) # modules statically linked with the server
  STRING(REPLACE "," ";" WITH_MODULE_LIST ${WITH_MODULES})
  FOREACH(static_mod ${WITH_MODULE_LIST})
    STRING(REGEX MATCH   "[^/]+\\.c"           mod_basename    ${static_mod})
    STRING(REGEX REPLACE "^mod_(.*)\\.c" "\\1" mod_module_name ${mod_basename})     
    SET(builtin_module_shortnames "${builtin_module_shortnames} ${mod_module_name}")
    CONFIGURE_FILE(${static_mod} ${PROJECT_BINARY_DIR}/ COPYONLY)
    SET(extra_builtin_modules ${extra_builtin_modules} ${PROJECT_BINARY_DIR}/${mod_basename})
  ENDFOREACH()
  EXECUTE_PROCESS(COMMAND cmd /c "echo ${builtin_module_shortnames}| awk -f ${CMAKE_CURRENT_SOURCE_DIR}/build/build-modules-c.awk > ${PROJECT_BINARY_DIR}/modules.c" RESULT_VARIABLE rv)
  IF(rv)
    MESSAGE(FATAL_ERROR "build-modules-c.awk failed (${rv})")
  ENDIF()
ELSE()
  # no extra built-in modules; use the default modules.c to avoid the awk prereq
  CONFIGURE_FILE(${CMAKE_CURRENT_SOURCE_DIR}/os/win32/modules.c ${PROJECT_BINARY_DIR}/ COPYONLY)
ENDIF()

# for easy reference from .dll/.so builds
CONFIGURE_FILE(os/win32/BaseAddr.ref ${PROJECT_BINARY_DIR}/ COPYONLY)

ADD_EXECUTABLE(gen_test_char server/gen_test_char.c)
GET_TARGET_PROPERTY(GEN_TEST_CHAR_EXE gen_test_char LOCATION)
ADD_CUSTOM_COMMAND(
  COMMENT "Generating character tables, test_char.h, for current locale"
  DEPENDS gen_test_char
  COMMAND ${GEN_TEST_CHAR_EXE} > ${PROJECT_BINARY_DIR}/test_char.h
  OUTPUT ${PROJECT_BINARY_DIR}/test_char.h
)
ADD_CUSTOM_TARGET(
  test_char_header ALL
  DEPENDS ${PROJECT_BINARY_DIR}/test_char.h
)

SET(HTTPD_MAIN_SOURCES
  server/main.c
)

SET(LIBHTTPD_SOURCES
  ${extra_builtin_modules}
  ${PROJECT_BINARY_DIR}/modules.c
  modules/arch/win32/mod_win32.c
  modules/core/mod_so.c
  modules/http/byterange_filter.c
  modules/http/chunk_filter.c
  modules/http/http_core.c
  modules/http/http_etag.c
  modules/http/http_filters.c
  modules/http/http_protocol.c
  modules/http/http_request.c
  os/win32/ap_regkey.c
  os/win32/util_win32.c
  server/buildmark.c
  server/config.c
  server/connection.c
  server/core.c
  server/core_filters.c
  server/eoc_bucket.c
  server/eor_bucket.c
  server/error_bucket.c
  server/listen.c
  server/log.c
  server/mpm/winnt/child.c
  server/mpm/winnt/mpm_winnt.c
  server/mpm/winnt/nt_eventlog.c
  server/mpm/winnt/service.c
  server/mpm_common.c
  server/protocol.c
  server/provider.c
  server/request.c
  server/ssl.c
  server/scoreboard.c
  server/util.c
  server/util_cfgtree.c
  server/util_cookies.c
  server/util_debug.c
  server/util_expr_eval.c
  server/util_expr_parse.c
  server/util_fcgi.c
  server/util_expr_scan.c
  server/util_filter.c
  server/util_md5.c
  server/util_mutex.c
  server/util_pcre.c
  server/util_regex.c
  server/util_script.c
  server/util_time.c
  server/util_xml.c
  server/vhost.c
)

CONFIGURE_FILE(os/win32/win32_config_layout.h
               ${PROJECT_BINARY_DIR}/ap_config_layout.h)

SET(HTTPD_INCLUDE_DIRECTORIES
  ${PROJECT_BINARY_DIR}
  ${EXTRA_INCLUDES}
  # see discussion in cmake bug 13188 regarding oddities with relative paths
  ${CMAKE_CURRENT_SOURCE_DIR}/include
  ${CMAKE_CURRENT_SOURCE_DIR}/os/win32
  ${CMAKE_CURRENT_SOURCE_DIR}/modules/core
  ${CMAKE_CURRENT_SOURCE_DIR}/modules/database
  ${CMAKE_CURRENT_SOURCE_DIR}/modules/dav/main
  ${CMAKE_CURRENT_SOURCE_DIR}/modules/filters
  ${CMAKE_CURRENT_SOURCE_DIR}/modules/generators
  ${CMAKE_CURRENT_SOURCE_DIR}/modules/http2
  ${CMAKE_CURRENT_SOURCE_DIR}/modules/md
  ${CMAKE_CURRENT_SOURCE_DIR}/modules/proxy
  ${CMAKE_CURRENT_SOURCE_DIR}/modules/session
  ${CMAKE_CURRENT_SOURCE_DIR}/modules/ssl
  ${CMAKE_CURRENT_SOURCE_DIR}/server
  ${CMAKE_CURRENT_SOURCE_DIR}/server/mpm/winnt
  ${APR_INCLUDE_DIR}
  ${PCRE_INCLUDE_DIR}
)

# The .h files we install from outside the main include directory
# largely parallel the include directories above.
SET(other_installed_h
  ${PROJECT_BINARY_DIR}/ap_config_layout.h
  ${CMAKE_CURRENT_SOURCE_DIR}/os/win32/os.h
  ${CMAKE_CURRENT_SOURCE_DIR}/modules/cache/mod_cache.h
  ${CMAKE_CURRENT_SOURCE_DIR}/modules/cache/cache_common.h
  ${CMAKE_CURRENT_SOURCE_DIR}/modules/core/mod_so.h
  ${CMAKE_CURRENT_SOURCE_DIR}/modules/core/mod_watchdog.h
  ${CMAKE_CURRENT_SOURCE_DIR}/modules/database/mod_dbd.h
  ${CMAKE_CURRENT_SOURCE_DIR}/modules/dav/main/mod_dav.h
  ${CMAKE_CURRENT_SOURCE_DIR}/modules/filters/mod_include.h
  ${CMAKE_CURRENT_SOURCE_DIR}/modules/filters/mod_xml2enc.h
  ${CMAKE_CURRENT_SOURCE_DIR}/modules/generators/mod_cgi.h
  ${CMAKE_CURRENT_SOURCE_DIR}/modules/generators/mod_status.h
  ${CMAKE_CURRENT_SOURCE_DIR}/modules/http2/mod_http2.h
  ${CMAKE_CURRENT_SOURCE_DIR}/modules/loggers/mod_log_config.h
  ${CMAKE_CURRENT_SOURCE_DIR}/modules/mappers/mod_rewrite.h
  ${CMAKE_CURRENT_SOURCE_DIR}/modules/proxy/mod_proxy.h
  ${CMAKE_CURRENT_SOURCE_DIR}/modules/session/mod_session.h
  ${CMAKE_CURRENT_SOURCE_DIR}/modules/ssl/mod_ssl.h
  ${CMAKE_CURRENT_SOURCE_DIR}/modules/ssl/mod_ssl_openssl.h
)
# When mod_serf is buildable, don't forget to copy modules/proxy/mod_serf.h

INCLUDE_DIRECTORIES(${HTTPD_INCLUDE_DIRECTORIES})

SET(HTTPD_SYSTEM_LIBS
  ws2_32
  mswsock
)

###########   HTTPD MODULES     ############
SET(LoadModules)
SET(mods_built_and_loaded)
SET(mods_built_but_not_loaded)
SET(mods_omitted)
FOREACH (mod ${MODULE_PATHS})
  # Build different forms of the module name; e.g., 
  #   mod_name->mod_cgi, mod_module_name->cgi_module, mod_shortname->cgi
  STRING(REGEX REPLACE ".*/(mod_[^\\+]+)" "\\1"        mod_name        ${mod})
  STRING(REGEX REPLACE "mod_(.*)"         "\\1_module" mod_module_name ${mod_name})
  STRING(REGEX REPLACE "mod_(.*)"         "\\1"        mod_shortname   ${mod_name})

  # Is it enabled?
  STRING(TOUPPER "ENABLE_${mod_shortname}" enable_mod)
  SET(enable_mod_val ${${enable_mod}})

  # Is ENABLE_MODULES set to a higher value?
  GET_MOD_ENABLE_RANK(${mod_name} ${enable_mod_val} this_mod_rank)
  IF(this_mod_rank LESS enable_modules_rank)
    # Use the value from ENABLE_MODULES
    SET(enable_mod_val ${ENABLE_MODULES})
  ENDIF()

  IF(NOT ${enable_mod_val} STREQUAL "O") # build of module is desired
    SET(mod_requires "${mod_name}_requires")
    STRING(TOUPPER ${enable_mod_val} enable_mod_val_upper)
    IF(NOT "${${mod_requires}}" STREQUAL "") # module has some prerequisite
      FOREACH (required ${${mod_requires}})
        IF(NOT ${required}) # prerequisite doesn't exist
          IF(NOT ${enable_mod_val} STREQUAL ${enable_mod_val_upper}) # lower case, so optional based on prereq
            MESSAGE(STATUS "${mod_name} was requested but couldn't be built due to a missing prerequisite (${required})")
            SET(enable_mod_val_upper "O") # skip due to missing prerequisite
          ELSE() # must be upper case "A" or "I" (or coding error above)
            MESSAGE(FATAL_ERROR "${mod_name} was requested but couldn't be built due to a missing prerequisite (${required})")
          ENDIF()
        ENDIF()
      ENDFOREACH()
    ENDIF()
    # map a->A, i->I, O->O for remaining logic since prereq checking is over
    SET(enable_mod_val ${enable_mod_val_upper})
  ENDIF()
  
  IF(${enable_mod_val} STREQUAL "O")
    # ignore
    SET(mods_omitted ${mods_omitted} ${mod_name})
  ELSE()
    # Handle whether or not the LoadModule is commented out.
    IF(${enable_mod_val} STREQUAL "A")
      SET(LoadModules "${LoadModules}LoadModule ${mod_module_name} modules/${mod_name}.so\n")
      SET(mods_built_and_loaded ${mods_built_and_loaded} ${mod_name})
    ELSEIF(${enable_mod_val} STREQUAL "I")
      SET(LoadModules "${LoadModules}# LoadModule ${mod_module_name} modules/${mod_name}.so\n")
      SET(mods_built_but_not_loaded ${mods_built_but_not_loaded} ${mod_name})
    ELSE()
      MESSAGE(FATAL_ERROR "${enable_mod} must be set to \"A\", \"I\", or \"O\" instead of \"${enable_mod_val}\"")
    ENDIF()

    # Handle building it.
    SET(mod_main_source "${mod_name}_main_source")
    SET(mod_extra_sources "${mod_name}_extra_sources")

    IF("${${mod_main_source}}" STREQUAL "")
      SET(tmp_mod_main_source "${mod}.c")
    ELSE()
      SET(tmp_mod_main_source ${${mod_main_source}})
    ENDIF()
    SET(all_mod_sources ${tmp_mod_main_source} ${${mod_extra_sources}})
    ADD_LIBRARY(${mod_name} SHARED ${all_mod_sources} build/win32/httpd.rc)
    SET(install_modules ${install_modules} ${mod_name})
    SET(install_modules_pdb ${install_modules_pdb} "$<TARGET_PDB_FILE:${mod_name}>")
    IF("${${mod_name}_install_lib}")
      SET(installed_mod_libs_exps
          ${installed_mod_libs_exps}
          "$<TARGET_LINKER_FILE:${mod_name}>"
          "$<TARGET_LINKER_FILE_DIR:${mod_name}>/${mod_name}.exp"
      )
    ENDIF()
    SET(mod_extra_libs "${mod_name}_extra_libs")
    SET_TARGET_PROPERTIES(${mod_name} PROPERTIES
      SUFFIX .so
      LINK_FLAGS /base:@${PROJECT_BINARY_DIR}/BaseAddr.ref,${mod_name}.so
    )
    TARGET_LINK_LIBRARIES(${mod_name} ${${mod_extra_libs}} libhttpd ${EXTRA_LIBS} ${APR_LIBRARIES} ${HTTPD_SYSTEM_LIBS})
    DEFINE_WITH_BLANKS(define_long_name "LONG_NAME" "${mod_name} for Apache HTTP Server")
    SET_TARGET_PROPERTIES(${mod_name} PROPERTIES COMPILE_FLAGS "${define_long_name} -DBIN_NAME=${mod_name}.so ${EXTRA_COMPILE_FLAGS}")

    # Extra defines?
    SET(mod_extra_defines "${mod_name}_extra_defines")
    IF(NOT ${${mod_extra_defines}} STREQUAL "")
      SET_TARGET_PROPERTIES(${mod_name} PROPERTIES COMPILE_DEFINITIONS ${${mod_extra_defines}})
    ENDIF()

    # Extra includes?
    SET(mod_extra_includes "${mod_name}_extra_includes")
    IF(NOT "${${mod_extra_includes}}" STREQUAL "")
      SET(tmp_includes ${HTTPD_INCLUDE_DIRECTORIES} ${${mod_extra_includes}})
      SET_TARGET_PROPERTIES(${mod_name} PROPERTIES INCLUDE_DIRECTORIES "${tmp_includes}")
      GET_PROPERTY(tmp_includes TARGET ${mod_name} PROPERTY INCLUDE_DIRECTORIES)
    ENDIF()

  ENDIF()
ENDFOREACH()

###########   HTTPD LIBRARIES   ############
ADD_LIBRARY(libhttpd SHARED ${LIBHTTPD_SOURCES} build/win32/httpd.rc)
SET_TARGET_PROPERTIES(libhttpd PROPERTIES
  LINK_FLAGS /base:@${PROJECT_BINARY_DIR}/BaseAddr.ref,libhttpd.dll
)
SET(install_targets ${install_targets} libhttpd)
SET(install_bin_pdb ${install_bin_pdb} $<TARGET_PDB_FILE:libhttpd>)
TARGET_LINK_LIBRARIES(libhttpd ${EXTRA_LIBS} ${APR_LIBRARIES} ${PCRE_LIBRARIES} ${HTTPD_SYSTEM_LIBS})
DEFINE_WITH_BLANKS(define_long_name "LONG_NAME" "Apache HTTP Server Core")
SET_TARGET_PROPERTIES(libhttpd PROPERTIES COMPILE_FLAGS "-DAP_DECLARE_EXPORT ${define_long_name} ${PCRE_CFLAGS} -DBIN_NAME=libhttpd.dll ${EXTRA_COMPILE_FLAGS}")
ADD_DEPENDENCIES(libhttpd test_char_header)

###########   HTTPD EXECUTABLES   ##########
ADD_EXECUTABLE(httpd server/main.c build/win32/httpd.rc)
SET(install_targets ${install_targets} httpd)
SET(install_bin_pdb ${install_bin_pdb} $<TARGET_PDB_FILE:httpd>)
DEFINE_WITH_BLANKS(define_long_name "LONG_NAME" "Apache HTTP Server")
SET_TARGET_PROPERTIES(httpd PROPERTIES COMPILE_FLAGS "-DAPP_FILE ${define_long_name} -DBIN_NAME=httpd.exe -DICON_FILE=${CMAKE_SOURCE_DIR}/build/win32/apache.ico ${EXTRA_COMPILE_FLAGS}")
TARGET_LINK_LIBRARIES(httpd libhttpd ${EXTRA_LIBS})

SET(standard_support
  ab
  htcacheclean
  htdbm
  htdigest
  htpasswd
  httxt2dbm
  logresolve
  rotatelogs
)

SET(htdbm_extra_sources support/passwd_common.c)
SET(htpasswd_extra_sources support/passwd_common.c)

FOREACH(pgm ${standard_support})
  SET(extra_sources ${pgm}_extra_sources)
  ADD_EXECUTABLE(${pgm} support/${pgm}.c ${${extra_sources}} build/win32/httpd.rc)
  SET(install_targets ${install_targets} ${pgm})
  SET(install_bin_pdb ${install_bin_pdb} $<TARGET_PDB_FILE:${pgm}>)
  DEFINE_WITH_BLANKS(define_long_name "LONG_NAME" "Apache HTTP Server ${pgm} program")
  SET_TARGET_PROPERTIES(${pgm} PROPERTIES COMPILE_FLAGS "-DAPP_FILE ${define_long_name} -DBIN_NAME=${pgm}.exe ${EXTRA_COMPILE_FLAGS}")
  TARGET_LINK_LIBRARIES(${pgm} ${EXTRA_LIBS} ${APR_LIBRARIES})
ENDFOREACH()

IF(OPENSSL_FOUND)
  ADD_EXECUTABLE(abs support/ab.c build/win32/httpd.rc)
  SET(install_targets ${install_targets} abs)
  SET(install_bin_pdb ${install_bin_pdb} $<TARGET_PDB_FILE:abs>)
  SET_TARGET_PROPERTIES(abs PROPERTIES COMPILE_DEFINITIONS HAVE_OPENSSL)
  SET(tmp_includes ${HTTPD_INCLUDE_DIRECTORIES} ${OPENSSL_INCLUDE_DIR})
  SET_TARGET_PROPERTIES(abs PROPERTIES INCLUDE_DIRECTORIES "${tmp_includes}")
  DEFINE_WITH_BLANKS(define_long_name "LONG_NAME" "Apache HTTP Server ab/SSL program")
  SET_TARGET_PROPERTIES(abs PROPERTIES COMPILE_FLAGS "-DAPP_FILE ${define_long_name} -DBIN_NAME=abs.exe ${EXTRA_COMPILE_FLAGS}")
  TARGET_LINK_LIBRARIES(abs ${EXTRA_LIBS} ${APR_LIBRARIES} ${OPENSSL_LIBRARIES})
ENDIF()
GET_PROPERTY(tmp_includes TARGET ab PROPERTY INCLUDE_DIRECTORIES)

# getting duplicate manifest error with ApacheMonitor
# ADD_EXECUTABLE(ApacheMonitor support/win32/ApacheMonitor.c support/win32/ApacheMonitor.rc)
# SET(install_targets ${install_targets} ApacheMonitor)
# SET(install_bin_pdb ${install_bin_pdb} $<TARGET_PDB_FILE:ApacheMonitor>)
# SET_TARGET_PROPERTIES(ApacheMonitor PROPERTIES WIN32_EXECUTABLE TRUE)
# SET_TARGET_PROPERTIES(ApacheMonitor PROPERTIES COMPILE_FLAGS "-DAPP_FILE -DLONG_NAME=ApacheMonitor -DBIN_NAME=ApacheMonitor.exe ${EXTRA_COMPILE_FLAGS}")
# TARGET_LINK_LIBRARIES(ApacheMonitor ${EXTRA_LIBS} ${HTTPD_SYSTEM_LIBS} comctl32 wtsapi32)

###########  CONFIGURATION FILES ###########
# Set up variables used in the .conf file templates
SET(LoadModule          "${LoadModules}")
SET(Port                "80" CACHE STRING "http port to listen on")
SET(SSLPort             "443" CACHE STRING "https port to listen on")
SET(ServerRoot          "${CMAKE_INSTALL_PREFIX}")
SET(exp_cgidir          "${CMAKE_INSTALL_PREFIX}/cgi-bin")
SET(exp_htdocsdir       "${CMAKE_INSTALL_PREFIX}/htdocs")
SET(exp_iconsdir        "${CMAKE_INSTALL_PREFIX}/icons")
SET(exp_errordir        "${CMAKE_INSTALL_PREFIX}/error")
SET(exp_manualdir       "${CMAKE_INSTALL_PREFIX}/manual")
SET(rel_logfiledir      "logs")
SET(rel_runtimedir      "logs")
SET(rel_sysconfdir      "conf")
FILE(GLOB_RECURSE conffiles RELATIVE ${CMAKE_SOURCE_DIR}/docs/conf "docs/conf/*")
FOREACH(template ${conffiles})
  STRING(REPLACE ".conf.in" ".conf" conf ${template})
  FILE(READ "docs/conf/${template}" template_text)
    IF(template MATCHES ".conf.in$")
      # substitute @var@/@@var@@ in .conf.in
      STRING(REPLACE "@@" "@" template_text ${template_text})
      STRING(CONFIGURE "${template_text}" template_text @ONLY)
    ENDIF()
  FILE(WRITE ${CMAKE_BINARY_DIR}/conf/original/${conf} "${template_text}")
  FILE(WRITE ${CMAKE_BINARY_DIR}/conf/${conf} "${template_text}")
ENDFOREACH()

###########   INSTALLATION   ###########
INSTALL(TARGETS ${install_targets}
        RUNTIME DESTINATION bin
        LIBRARY DESTINATION lib
        ARCHIVE DESTINATION lib
       )
INSTALL(TARGETS ${install_modules}
        RUNTIME DESTINATION modules
       )

IF(INSTALL_PDB)
  INSTALL(FILES ${install_bin_pdb}
          DESTINATION bin
          CONFIGURATIONS RelWithDebInfo Debug)

  INSTALL(FILES ${install_modules_pdb}
          DESTINATION modules
          CONFIGURATIONS RelWithDebInfo Debug)
ENDIF()

INSTALL(DIRECTORY include/ DESTINATION include
    FILES_MATCHING PATTERN "*.h"
)
INSTALL(FILES ${other_installed_h} DESTINATION include)
INSTALL(FILES ${installed_mod_libs_exps} DESTINATION lib)
INSTALL(FILES "$<TARGET_LINKER_FILE_DIR:libhttpd>/libhttpd.exp" DESTINATION LIB)

IF(INSTALL_MANUAL) # Silly?  This takes a while, and a dev doesn't need it.
  INSTALL(DIRECTORY docs/manual/ DESTINATION manual)
ENDIF()

INSTALL(DIRECTORY DESTINATION logs)
INSTALL(DIRECTORY DESTINATION cgi-bin)

INSTALL(CODE "EXECUTE_PROCESS(COMMAND perl \"${CMAKE_CURRENT_SOURCE_DIR}/build/cpR_noreplace.pl\" \"${CMAKE_CURRENT_SOURCE_DIR}/docs/error\" \"${CMAKE_INSTALL_PREFIX}/error\" ifdestmissing)")

INSTALL(CODE "EXECUTE_PROCESS(COMMAND perl \"${CMAKE_CURRENT_SOURCE_DIR}/build/cpR_noreplace.pl\" \"${CMAKE_CURRENT_SOURCE_DIR}/docs/docroot\" \"${CMAKE_INSTALL_PREFIX}/htdocs\" ifdestmissing)")

INSTALL(CODE "EXECUTE_PROCESS(COMMAND perl \"${CMAKE_CURRENT_SOURCE_DIR}/build/cpR_noreplace.pl\" \"${CMAKE_CURRENT_SOURCE_DIR}/docs/icons\" \"${CMAKE_INSTALL_PREFIX}/icons\" ifdestmissing)")

# Copy generated .conf files from the build directory to the install,
# without overwriting stuff already there.
INSTALL(CODE "EXECUTE_PROCESS(COMMAND perl \"${CMAKE_CURRENT_SOURCE_DIR}/build/cpR_noreplace.pl\" \"${CMAKE_BINARY_DIR}/conf\" \"${CMAKE_INSTALL_PREFIX}/conf\")")
# But conf/original is supposed to be overwritten.
# Note: FILE(TO_NATIVE_PATH ...) leaves the backslashes unescaped, which
#       generates warnings.  Just do it manually since this build only supports
#       Windows anyway.
STRING(REPLACE "/" "\\\\" native_src ${CMAKE_BINARY_DIR}/conf/original)
STRING(REPLACE "/" "\\\\" native_dest ${CMAKE_INSTALL_PREFIX}/conf/original)
INSTALL(CODE "EXECUTE_PROCESS(COMMAND xcopy \"${native_src}\" \"${native_dest}\" /Q /S /Y)")

STRING(TOUPPER "${CMAKE_BUILD_TYPE}" buildtype)
MESSAGE(STATUS "")
MESSAGE(STATUS "")
MESSAGE(STATUS "Apache httpd configuration summary:")
MESSAGE(STATUS "")
MESSAGE(STATUS "  Build type ...................... : ${CMAKE_BUILD_TYPE}")
MESSAGE(STATUS "  Install .pdb (if available)...... : ${INSTALL_PDB}")
MESSAGE(STATUS "  Install manual .................. : ${INSTALL_MANUAL}")
MESSAGE(STATUS "  Install prefix .................. : ${CMAKE_INSTALL_PREFIX}")
MESSAGE(STATUS "  C compiler ...................... : ${CMAKE_C_COMPILER}")
MESSAGE(STATUS "  APR include directory ........... : ${APR_INCLUDE_DIR}")
MESSAGE(STATUS "  APR libraries ................... : ${APR_LIBRARIES}")
MESSAGE(STATUS "  OpenSSL include directory ....... : ${OPENSSL_INCLUDE_DIR}")
MESSAGE(STATUS "  OpenSSL libraries ............... : ${OPENSSL_LIBRARIES}")
MESSAGE(STATUS "  PCRE include directory .......... : ${PCRE_INCLUDE_DIR}")
MESSAGE(STATUS "  PCRE libraries .................. : ${PCRE_LIBRARIES}")
MESSAGE(STATUS "  libxml2 iconv prereq include dir. : ${LIBXML2_ICONV_INCLUDE_DIR}")
MESSAGE(STATUS "  libxml2 iconv prereq libraries .. : ${LIBXML2_ICONV_LIBRARIES}")
MESSAGE(STATUS "  Brotli include directory......... : ${BROTLI_INCLUDE_DIR}")
MESSAGE(STATUS "  Brotli libraries ................ : ${BROTLI_LIBRARIES}")
MESSAGE(STATUS "  Curl include directory........... : ${CURL_INCLUDE_DIR}")
MESSAGE(STATUS "  Jansson libraries ............... : ${JANSSON_LIBRARIES}")
MESSAGE(STATUS "  Extra include directories ....... : ${EXTRA_INCLUDES}")
MESSAGE(STATUS "  Extra compile flags ............. : ${EXTRA_COMPILE_FLAGS}")
MESSAGE(STATUS "  Extra libraries ................. : ${EXTRA_LIBS}")

MESSAGE(STATUS "  Modules built and loaded:")
FOREACH(mod ${mods_built_and_loaded})
  MESSAGE(STATUS "    ${mod}")
ENDFOREACH()

MESSAGE(STATUS "  Modules built but not loaded:")
FOREACH(mod ${mods_built_but_not_loaded})
  MESSAGE(STATUS "    ${mod}")
ENDFOREACH()

MESSAGE(STATUS "  Modules not built:")
FOREACH(mod ${mods_omitted})
  MESSAGE(STATUS "    ${mod}")
ENDFOREACH()
