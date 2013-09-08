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

# See what version we're building.  Just look at AP_SERVER_MINORVERSION_NUMBER
SET(minorversion_regex "^#define AP_SERVER_MINORVERSION_NUMBER ([0-9]+)$")
FILE(STRINGS ${CMAKE_CURRENT_SOURCE_DIR}/include/ap_release.h minorversion REGEX ${minorversion_regex})
STRING(REGEX REPLACE ${minorversion_regex} "\\1" minorversion ${minorversion})

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
IF(EXISTS "${CMAKE_INSTALL_PREFIX}/lib/pcred.lib")
  SET(default_pcre_libraries ${CMAKE_INSTALL_PREFIX}/lib/pcred.lib)
ELSE()
  SET(default_pcre_libraries ${CMAKE_INSTALL_PREFIX}/lib/pcre.lib)
ENDIF()

SET(APR_INCLUDE_DIR       "${CMAKE_INSTALL_PREFIX}/include" CACHE STRING "Directory with APR[-Util] include files")
SET(APR_LIBRARIES         ${default_apr_libraries}       CACHE STRING "APR libraries to link with")
SET(PCRE_INCLUDE_DIR      "${CMAKE_INSTALL_PREFIX}/include" CACHE STRING "Directory with PCRE include files")
SET(PCRE_LIBRARIES        ${default_pcre_libraries}      CACHE STRING "PCRE libraries to link with")
SET(LIBXML2_ICONV_INCLUDE_DIR     ""                     CACHE STRING "Directory with iconv include files for libxml2")
SET(LIBXML2_ICONV_LIBRARIES       ""                     CACHE STRING "iconv libraries to link with for libxml2")
# end support library configuration

# Misc. options
SET(WITH_MODULES          ""                             CACHE STRING "comma-separated paths to single-file modules to statically link into the server")
SET(EXTRA_INCLUDE_DIRS    ""                             CACHE STRING "extra include directories")

IF(NOT EXISTS "${APR_INCLUDE_DIR}/apr.h")
  MESSAGE(FATAL_ERROR "APR include directory ${APR_INCLUDE_DIR} is not correct.")
ENDIF()
FOREACH(onelib ${APR_LIBRARIES})
  IF(NOT EXISTS ${onelib})
    MESSAGE(FATAL_ERROR "APR library ${onelib} was not found.")
  ENDIF()
ENDFOREACH()

# Figure out what APR/APU features are available
#
# CHECK_APR_FEATURE checks for features defined to 1 or 0 in apr.h or apu.h
# The symbol representing the feature will be set to TRUE or FALSE for 
# compatibility with the feature tests set by FindFooPackage.
#
# (unclear why CHECK_SYMBOL_EXISTS is needed, but I was getting "found" for anything 
# not defined to either 1 or 0)

MACRO(CHECK_APR_FEATURE which_define)
  CHECK_SYMBOL_EXISTS(${which_define} "${APR_INCLUDE_DIR}/apr.h;${APR_INCLUDE_DIR}/apu.h" tmp_${which_define})
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

MESSAGE(STATUS "")
MESSAGE(STATUS "Summary of feature detection:")
MESSAGE(STATUS "")
MESSAGE(STATUS "LIBXML2_FOUND ............ : ${LIBXML2_FOUND}")
MESSAGE(STATUS "LUA51_FOUND .............. : ${LUA51_FOUND}")
MESSAGE(STATUS "OPENSSL_FOUND ............ : ${OPENSSL_FOUND}")
MESSAGE(STATUS "ZLIB_FOUND ............... : ${ZLIB_FOUND}")
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
  "modules/aaa/mod_access_compat.c+A+mod_access compatibility"
  "modules/aaa/mod_allowmethods.c+I+restrict allowed HTTP methods"
  "modules/aaa/mod_auth_basic.c+A+basic authentication"
  "modules/aaa/mod_auth_digest.c+I+RFC2617 Digest authentication"
  "modules/aaa/mod_auth_form.c+I+form authentication"
  "modules/aaa/mod_authn_anon.c+I+anonymous user authentication control"
  "modules/aaa/mod_authn_core.c+A+core authentication module"
  "modules/aaa/mod_authn_dbd.c+I+SQL-based authentication control"
  "modules/aaa/mod_authn_dbm.c+I+DBM-based authentication control"
  "modules/aaa/mod_authn_file.c+A+file-based authentication control"
  "modules/aaa/mod_authn_socache.c+I+Cached authentication control"
  "modules/aaa/mod_authnz_ldap.c+i+LDAP based authentication"
  "modules/aaa/mod_authz_core.c+A+core authorization provider vector module"
  "modules/aaa/mod_authz_dbd.c+I+SQL based authorization and Login/Session support"
  "modules/aaa/mod_authz_dbm.c+I+DBM-based authorization control"
  "modules/aaa/mod_authz_groupfile.c+A+'require group' authorization control"
  "modules/aaa/mod_authz_host.c+A+host-based authorization control"
  "modules/aaa/mod_authz_owner.c+I+'require file-owner' authorization control"
  "modules/aaa/mod_authz_user.c+A+'require user' authorization control"
  "modules/arch/win32/mod_isapi.c+I+isapi extension support"
  "modules/cache/mod_cache.c+I+dynamic file caching.  At least one storage management module (e.g. mod_cache_disk) is also necessary."
  "modules/cache/mod_cache_disk.c+I+disk caching module"
  "modules/cache/mod_cache_socache.c+I+shared object caching module"
  "modules/cache/mod_file_cache.c+I+File cache"
  "modules/cache/mod_socache_dbm.c+I+dbm small object cache provider"
  "modules/cache/mod_socache_dc.c+O+distcache small object cache provider"
  "modules/cache/mod_socache_memcache.c+I+memcache small object cache provider"
  "modules/cache/mod_socache_shmcb.c+I+ shmcb small object cache provider"
  "modules/cluster/mod_heartbeat.c+I+Generates Heartbeats"
  "modules/cluster/mod_heartmonitor.c+I+Collects Heartbeats"
  "modules/core/mod_macro.c+I+Define and use macros in configuration files"
  "modules/core/mod_watchdog.c+I+Watchdog module"
  "modules/database/mod_dbd.c+I+Apache DBD Framework"
  "modules/dav/fs/mod_dav_fs.c+I+DAV provider for the filesystem."
  "modules/dav/lock/mod_dav_lock.c+I+DAV provider for generic locking"
  "modules/dav/main/mod_dav.c+I+WebDAV protocol handling."
  "modules/debugging/mod_bucketeer.c+O+buckets manipulation filter.  Useful only for developers and testing purposes."
  "modules/debugging/mod_dumpio.c+I+I/O dump filter"
  "modules/echo/mod_echo.c+O+ECHO server"
  "modules/examples/mod_case_filter.c+O+Example uppercase conversion filter"
  "modules/examples/mod_case_filter_in.c+O+Example uppercase conversion input filter"
  "modules/examples/mod_example_hooks.c+O+Example hook callback handler module"
  "modules/examples/mod_example_ipc.c+O+Example of shared memory and mutex usage"
  "modules/filters/mod_buffer.c+I+Filter Buffering"
  "modules/filters/mod_charset_lite.c+i+character set translation"
  "modules/filters/mod_data.c+O+RFC2397 data encoder"
  "modules/filters/mod_deflate.c+i+Deflate transfer encoding support"
  "modules/filters/mod_ext_filter.c+I+external filter module"
  "modules/filters/mod_filter.c+A+Smart Filtering"
  "modules/filters/mod_include.c+I+Server Side Includes"
  "modules/filters/mod_proxy_html.c+i+Fix HTML Links in a Reverse Proxy"
  "modules/filters/mod_ratelimit.c+I+Output Bandwidth Limiting"
  "modules/filters/mod_reflector.c+O+Reflect request through the output filter stack"
  "modules/filters/mod_reqtimeout.c+A+Limit time waiting for request from client"
  "modules/filters/mod_request.c+I+Request Body Filtering"
  "modules/filters/mod_sed.c+I+filter request and/or response bodies through sed"
  "modules/filters/mod_substitute.c+I+response content rewrite-like filtering"
  "modules/filters/mod_xml2enc.c+i+i18n support for markup filters"
  "modules/generators/mod_asis.c+I+as-is filetypes"
  "modules/generators/mod_autoindex.c+A+directory listing"
  "modules/generators/mod_cgi.c+I+CGI scripts"
  "modules/generators/mod_info.c+I+server information"
  "modules/generators/mod_status.c+I+process/thread monitoring"
  "modules/http/mod_mime.c+A+mapping of file-extension to MIME.  Disabling this module is normally not recommended."
  "modules/ldap/mod_ldap.c+i+LDAP caching and connection pooling services"
  "modules/loggers/mod_log_config.c+A+logging configuration.  You won't be able to log requests to the server without this module."
  "modules/loggers/mod_log_debug.c+I+configurable debug logging"
  "modules/loggers/mod_log_forensic.c+I+forensic logging"
  "modules/loggers/mod_logio.c+I+input and output logging"
  "modules/lua/mod_lua.c+i+Apache Lua Framework"
  "modules/mappers/mod_actions.c+I+Action triggering on requests"
  "modules/mappers/mod_alias.c+A+mapping of requests to different filesystem parts"
  "modules/mappers/mod_dir.c+A+directory request handling"
  "modules/mappers/mod_imagemap.c+I+server-side imagemaps"
  "modules/mappers/mod_negotiation.c+I+content negotiation"
  "modules/mappers/mod_rewrite.c+I+rule based URL manipulation"
  "modules/mappers/mod_speling.c+I+correct common URL misspellings"
  "modules/mappers/mod_userdir.c+I+mapping of requests to user-specific directories"
  "modules/mappers/mod_vhost_alias.c+I+mass virtual hosting module"
  "modules/metadata/mod_cern_meta.c+O+CERN-type meta files"
  "modules/metadata/mod_env.c+A+clearing/setting of ENV vars"
  "modules/metadata/mod_expires.c+I+Expires header control"
  "modules/metadata/mod_headers.c+A+HTTP header control"
  "modules/metadata/mod_ident.c+O+RFC 1413 identity check"
  "modules/metadata/mod_mime_magic.c+O+automagically determining MIME type"
  "modules/metadata/mod_remoteip.c+I+translate header contents to an apparent client remote_ip"
  "modules/metadata/mod_setenvif.c+A+basing ENV vars on headers"
  "modules/metadata/mod_unique_id.c+I+per-request unique ids"
  "modules/metadata/mod_usertrack.c+I+user-session tracking"
  "modules/metadata/mod_version.c+A+determining httpd version in config files"
  "modules/proxy/balancers/mod_lbmethod_bybusyness.c+I+Apache proxy Load balancing by busyness"
  "modules/proxy/balancers/mod_lbmethod_byrequests.c+I+Apache proxy Load balancing by request counting"
  "modules/proxy/balancers/mod_lbmethod_bytraffic.c+I+Apache proxy Load balancing by traffic counting"
  "modules/proxy/balancers/mod_lbmethod_heartbeat.c+I+Apache proxy Load balancing from Heartbeats"
  "modules/proxy/mod_proxy_ajp.c+I+Apache proxy AJP module.  Requires and is enabled by --enable-proxy."
  "modules/proxy/mod_proxy_balancer.c+I+Apache proxy BALANCER module.  Requires and is enabled by --enable-proxy."
  "modules/proxy/mod_proxy.c+I+Apache proxy module"
  "modules/proxy/mod_proxy_connect.c+I+Apache proxy CONNECT module.  Requires and is enabled by --enable-proxy."
  "modules/proxy/mod_proxy_express.c+I+mass reverse-proxy module. Requires --enable-proxy."
  "modules/proxy/mod_proxy_fcgi.c+I+Apache proxy FastCGI module.  Requires and is enabled by --enable-proxy."
  "modules/proxy/mod_proxy_ftp.c+I+Apache proxy FTP module.  Requires and is enabled by --enable-proxy."
  "modules/proxy/mod_proxy_http.c+I+Apache proxy HTTP module.  Requires and is enabled by --enable-proxy."
  "modules/proxy/mod_proxy_scgi.c+I+Apache proxy SCGI module.  Requires and is enabled by --enable-proxy."
  "modules/proxy/mod_proxy_wstunnel.c+I+Apache proxy Websocket Tunnel module.  Requires and is enabled by --enable-proxy."
  "modules/session/mod_session.c+I+session module"
  "modules/session/mod_session_cookie.c+I+session cookie module"
  "modules/session/mod_session_crypto.c+i+session crypto module"
  "modules/session/mod_session_dbd.c+I+session dbd module"
  "modules/slotmem/mod_slotmem_plain.c+I+slotmem provider that uses plain memory"
  "modules/slotmem/mod_slotmem_shm.c+I+slotmem provider that uses shared memory"
  "modules/ssl/mod_ssl.c+i+SSL/TLS support"
  "modules/test/mod_dialup.c+O+rate limits static files to dialup modem speeds"
  "modules/test/mod_optional_fn_export.c+O+example optional function exporter"
  "modules/test/mod_optional_fn_import.c+O+example optional function importer"
  "modules/test/mod_optional_hook_export.c+O+example optional hook exporter"
  "modules/test/mod_optional_hook_import.c+O+example optional hook importer"
)

IF(NOT ${minorversion} STREQUAL "4")
  # more modules in trunk
  SET(MODULE_LIST
      ${MODULE_LIST}
      "modules/aaa/mod_allowhandlers.c+I+restrict allowed handlers"
      "modules/aaa/mod_authnz_fcgi.c+I+FastCGI authorizer-based authentication and authorization"
      "modules/debugging/mod_firehose.c+O+Firehose dump filter"
      "modules/proxy/mod_serf.c+O+Reverse proxy module using Serf"
      "modules/test/mod_policy.c+I+HTTP protocol compliance filters"
  )
ENDIF()

# Define extra definitions, sources, headers, etc. required by some modules.
# This could be included in the master list of modules above, though it 
# certainly would get a lot more unreadable.
SET(mod_authz_dbd_extra_defines      AUTHZ_DBD_DECLARE_EXPORT)
SET(mod_authnz_ldap_requires         APR_HAS_LDAP)
SET(mod_authnz_ldap_extra_libs       mod_ldap)
SET(mod_cache_extra_defines          CACHE_DECLARE_EXPORT)
SET(mod_cache_extra_sources
  modules/cache/cache_storage.c      modules/cache/cache_util.c
)
SET(mod_cache_disk_extra_libs        mod_cache)
SET(mod_cache_socache_extra_libs     mod_cache)
SET(mod_charset_lite_requires        APR_HAS_XLATE)
SET(mod_dav_extra_defines            DAV_DECLARE_EXPORT)
SET(mod_dav_extra_sources
  modules/dav/main/liveprop.c        modules/dav/main/props.c
  modules/dav/main/std_liveprop.c    modules/dav/main/providers.c
  modules/dav/main/util.c            modules/dav/main/util_lock.c
)
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
SET(mod_heartbeat_extra_libs         mod_watchdog)
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
SET(mod_optional_hook_export_extra_defines AP_DECLARE_EXPORT) # bogus reuse of core API prefix
SET(mod_proxy_extra_defines          PROXY_DECLARE_EXPORT)
SET(mod_proxy_extra_sources          modules/proxy/proxy_util.c)
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
SET(mod_proxy_http_extra_libs        mod_proxy)
SET(mod_proxy_html_requires          LIBXML2_FOUND)
IF(LIBXML2_FOUND)
  SET(mod_proxy_html_extra_includes    "${LIBXML2_INCLUDE_DIR};${LIBXML2_ICONV_INCLUDE_DIR}")
  SET(mod_proxy_html_extra_libs        "${LIBXML2_LIBRARIES};${LIBXML2_ICONV_LIBRARIES}")
ENDIF()
SET(mod_proxy_scgi_extra_libs        mod_proxy)
SET(mod_proxy_wstunnel_extra_libs    mod_proxy)
SET(mod_ratelimit_extra_defines      AP_RL_DECLARE_EXPORT)
SET(mod_sed_extra_sources
  modules/filters/regexp.c           modules/filters/sed0.c
  modules/filters/sed1.c
)
SET(mod_session_extra_defines        SESSION_DECLARE_EXPORT)
SET(mod_session_cookie_extra_libs    mod_session)
SET(mod_session_crypto_requires      APU_HAVE_CRYPTO)
SET(mod_session_crypto_extra_libs    mod_session)
SET(mod_session_dbd_extra_libs       mod_session)
SET(mod_ssl_requires                 OPENSSL_FOUND)
IF(OPENSSL_FOUND)
  SET(mod_ssl_extra_includes           ${OPENSSL_INCLUDE_DIR})
  SET(mod_ssl_extra_libs               ${OPENSSL_LIBRARIES})
ENDIF()
SET(mod_ssl_extra_sources
  modules/ssl/ssl_engine_config.c    modules/ssl/ssl_engine_dh.c
  modules/ssl/ssl_engine_init.c      modules/ssl/ssl_engine_io.c
  modules/ssl/ssl_engine_kernel.c    modules/ssl/ssl_engine_log.c
  modules/ssl/ssl_engine_mutex.c     modules/ssl/ssl_engine_ocsp.c
  modules/ssl/ssl_engine_pphrase.c   modules/ssl/ssl_engine_rand.c
  modules/ssl/ssl_engine_vars.c      modules/ssl/ssl_scache.c
  modules/ssl/ssl_util.c             modules/ssl/ssl_util_ocsp.c
  modules/ssl/ssl_util_ssl.c         modules/ssl/ssl_util_stapling.c
)
SET(mod_status_extra_defines         STATUS_DECLARE_EXPORT)
SET(mod_xml2enc_requires             LIBXML2_FOUND)
IF(LIBXML2_FOUND)
  SET(mod_xml2enc_extra_includes     "${LIBXML2_INCLUDE_DIR};${LIBXML2_ICONV_INCLUDE_DIR}")
  SET(mod_xml2enc_extra_libs         "${LIBXML2_LIBRARIES};${LIBXML2_ICONV_LIBRARIES}")
ENDIF()
SET(mod_watchdog_extra_defines       AP_WD_DECLARE_EXPORT)

SET(MODULE_SRCS)

FOREACH (modinfo ${MODULE_LIST})
  STRING(REGEX REPLACE "([^+]*)\\+([^+]*)\\+([^+]*)" "\\1;\\2;\\3" modinfolist ${modinfo})
  SET(primarysourcefile)
  SET(defaultenable)
  SET(helptext)
  FOREACH(i ${modinfolist})
    IF("${primarysourcefile}" STREQUAL "")
      SET(primarysourcefile ${i})
    ELSEIF("${defaultenable}" STREQUAL "")
      SET(defaultenable ${i})
    ELSEIF("${helptext}" STREQUAL "")
      SET(helptext ${i})
    ELSE()
      MESSAGE(FATAL_ERROR "Unexpected field or plus sign in >${modinfo}<")
    ENDIF()
  ENDFOREACH()

  # MESSAGE("  primary source file: ${primarysourcefile}")
  # MESSAGE("enablement by default: ${defaultenable}")
  # MESSAGE("            help text: ${helptext}")

  STRING(REGEX MATCH   "[^/]+\\.c"        mod_basename   ${primarysourcefile})
  STRING(REGEX MATCH   "[^.]+"            mod_name       ${mod_basename})
  STRING(REGEX REPLACE "mod_(.*)"  "\\1"  mod_shortname  ${mod_name})

  STRING(TOUPPER "ENABLE_${mod_shortname}" mod_option_name)

  SET(${mod_option_name} ${defaultenable} CACHE STRING ${helptext})
  SET(MODULE_SRCS "${MODULE_SRCS};${primarysourcefile}")

ENDFOREACH()

SET(install_targets)
SET(install_modules) # special handling vs. other installed targets
SET(builtin_module_shortnames "win32 mpm_winnt http so") # core added automatically
SET(extra_builtin_modules) # the ones specified with -DWITH_MODULES=

IF(WITH_MODULES) # modules statically linked with the server
  STRING(REPLACE "," ";" WITH_MODULE_LIST ${WITH_MODULES})
  FOREACH(static_mod ${WITH_MODULE_LIST})
    STRING(REGEX MATCH "[^/]+\\.c"           mod_basename    ${static_mod})
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
  server/scoreboard.c
  server/util.c
  server/util_cfgtree.c
  server/util_cookies.c
  server/util_expr_eval.c
  server/util_expr_parse.c
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

IF(NOT ${minorversion} STREQUAL "4")
  # more libhttpd sources in trunk
  SET(LIBHTTPD_SOURCES
      ${LIBHTTPD_SOURCES}
      "server/util_fcgi.c"
  )
ENDIF()

CONFIGURE_FILE(os/win32/win32_config_layout.h
               ${PROJECT_BINARY_DIR}/ap_config_layout.h)

SET(HTTPD_INCLUDE_DIRECTORIES
  ${PROJECT_BINARY_DIR}
  ${EXTRA_INCLUDE_DIRS}
  # see discussion in cmake bug 13188 regarding oddities with relative paths
  ${CMAKE_CURRENT_SOURCE_DIR}/include
  ${CMAKE_CURRENT_SOURCE_DIR}/os/win32
  ${CMAKE_CURRENT_SOURCE_DIR}/modules/core
  ${CMAKE_CURRENT_SOURCE_DIR}/modules/database
  ${CMAKE_CURRENT_SOURCE_DIR}/modules/dav/main
  ${CMAKE_CURRENT_SOURCE_DIR}/modules/filters
  ${CMAKE_CURRENT_SOURCE_DIR}/modules/generators
  ${CMAKE_CURRENT_SOURCE_DIR}/modules/proxy
  ${CMAKE_CURRENT_SOURCE_DIR}/modules/session
  ${CMAKE_CURRENT_SOURCE_DIR}/modules/ssl
  ${CMAKE_CURRENT_SOURCE_DIR}/server
  ${APR_INCLUDE_DIR}
  ${PCRE_INCLUDE_DIR}
)

# The .h files we install from outside the main include directory
# largely parallel the include directories above.
SET(other_installed_h
  ${PROJECT_BINARY_DIR}/ap_config_layout.h
  ${CMAKE_CURRENT_SOURCE_DIR}/os/win32/os.h
  ${CMAKE_CURRENT_SOURCE_DIR}/modules/cache/mod_cache.h  
  ${CMAKE_CURRENT_SOURCE_DIR}/modules/core/mod_so.h
  ${CMAKE_CURRENT_SOURCE_DIR}/modules/core/mod_watchdog.h
  ${CMAKE_CURRENT_SOURCE_DIR}/modules/database/mod_dbd.h
  ${CMAKE_CURRENT_SOURCE_DIR}/modules/dav/main/mod_dav.h
  ${CMAKE_CURRENT_SOURCE_DIR}/modules/filters/mod_include.h
  ${CMAKE_CURRENT_SOURCE_DIR}/modules/filters/mod_xml2enc.h
  ${CMAKE_CURRENT_SOURCE_DIR}/modules/generators/mod_cgi.h
  ${CMAKE_CURRENT_SOURCE_DIR}/modules/generators/mod_status.h
  ${CMAKE_CURRENT_SOURCE_DIR}/modules/loggers/mod_log_config.h
  ${CMAKE_CURRENT_SOURCE_DIR}/modules/mappers/mod_rewrite.h
  ${CMAKE_CURRENT_SOURCE_DIR}/modules/proxy/mod_proxy.h
  ${CMAKE_CURRENT_SOURCE_DIR}/modules/session/mod_session.h
  ${CMAKE_CURRENT_SOURCE_DIR}/modules/ssl/mod_ssl.h
)

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
FOREACH (mod ${MODULE_SRCS})
  # Build different forms of the module name; e.g., 
  #   mod_short_name->mod_cgi.c, mod_name->mod_cgi, mod_module_name->cgi_module
  STRING(REGEX MATCH   "[^/]+\\.c"              mod_basename  ${mod})
  STRING(REGEX MATCH   "[^.]+"                  mod_name        ${mod_basename})
  STRING(REGEX REPLACE "^mod_(.*)" "\\1_module" mod_module_name ${mod_name})
  STRING(REGEX REPLACE "mod_(.*)"  "\\1"        mod_shortname   ${mod_name})

  # Is it enabled?
  STRING(TOUPPER "ENABLE_${mod_shortname}" enable_mod)
  SET(enable_mod_val ${${enable_mod}})

  IF(NOT ${enable_mod_val} STREQUAL "O") # build of module is desired
    SET(mod_requires "${mod_name}_requires")
    STRING(TOUPPER ${enable_mod_val} enable_mod_val_upper)
    IF(NOT ${${mod_requires}} STREQUAL "") # module has some prerequisite
      IF(NOT ${${mod_requires}}) # prerequisite doesn't exist
        IF(NOT ${enable_mod_val} STREQUAL ${enable_mod_val_upper}) # lower case, so optional based on prereq
          MESSAGE(STATUS "${mod_name} was requested but couldn't be built due to a missing prerequisite (${${mod_requires}})")
          SET(enable_mod_val_upper "O") # skip due to missing prerequisite
        ELSE() # must be upper case "A" or "I" (or coding error above)
          MESSAGE(FATAL_ERROR "${mod_name} was requested but couldn't be built due to a missing prerequisite (${${mod_requires}})")
        ENDIF()
      ENDIF()
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
      SET(tmp_mod_main_source ${mod})
    ELSE()
      SET(tmp_mod_main_source ${${mod_main_source}})
    ENDIF()
    SET(all_mod_sources ${tmp_mod_main_source} ${${mod_extra_sources}})
    ADD_LIBRARY(${mod_name} SHARED ${all_mod_sources})
    SET(install_modules ${install_modules} ${mod_name})
    SET(mod_extra_libs "${mod_name}_extra_libs")
    SET_TARGET_PROPERTIES(${mod_name} PROPERTIES SUFFIX .so)
    TARGET_LINK_LIBRARIES(${mod_name} ${${mod_extra_libs}} libhttpd ${APR_LIBRARIES} ${HTTPD_SYSTEM_LIBS})

    # Extra defines?
    SET(mod_extra_defines "${mod_name}_extra_defines")
    IF(NOT ${${mod_extra_defines}} STREQUAL "")
      SET_TARGET_PROPERTIES(${mod_name} PROPERTIES COMPILE_DEFINITIONS ${${mod_extra_defines}})
    ENDIF()

    # Extra includes?
    SET(mod_extra_includes "${mod_name}_extra_includes")
    IF(NOT "${${mod_extra_includes}}" STREQUAL "")
      SET(tmp_includes ${${mod_extra_includes}} ${HTTPD_INCLUDE_DIRECTORIES})
      SET_TARGET_PROPERTIES(${mod_name} PROPERTIES INCLUDE_DIRECTORIES "${tmp_includes}")
      GET_PROPERTY(tmp_includes TARGET ${mod_name} PROPERTY INCLUDE_DIRECTORIES)
    ENDIF()

  ENDIF()
ENDFOREACH()

###########   HTTPD LIBRARIES   ############
ADD_LIBRARY(libhttpd SHARED ${LIBHTTPD_SOURCES})
SET(install_targets ${install_targets} libhttpd)
TARGET_LINK_LIBRARIES(libhttpd ${APR_LIBRARIES} ${PCRE_LIBRARIES} ${HTTPD_SYSTEM_LIBS})
SET_TARGET_PROPERTIES(libhttpd PROPERTIES COMPILE_FLAGS -DAP_DECLARE_EXPORT)
ADD_DEPENDENCIES(libhttpd test_char_header)

###########   HTTPD EXECUTABLES   ##########
ADD_EXECUTABLE(httpd server/main.c build/win32/httpd.rc)
SET(install_targets ${install_targets} httpd)
SET_TARGET_PROPERTIES(httpd PROPERTIES COMPILE_FLAGS "-DLONG_NAME=\"\\\"Apache HTTP Server\\\"\" -DBIN_NAME=httpd.exe")
TARGET_LINK_LIBRARIES(httpd libhttpd)

ADD_EXECUTABLE(ab support/ab.c)
SET(install_targets ${install_targets} ab)
IF(OPENSSL_FOUND)
  SET_TARGET_PROPERTIES(ab PROPERTIES COMPILE_DEFINITIONS HAVE_OPENSSL)
  SET(tmp_includes ${HTTPD_INCLUDE_DIRECTORIES} ${OPENSSL_INCLUDE_DIR})
  SET_TARGET_PROPERTIES(ab PROPERTIES INCLUDE_DIRECTORIES "${tmp_includes}")
  TARGET_LINK_LIBRARIES(ab ${APR_LIBRARIES} ${OPENSSL_LIBRARIES})
ELSE()
  TARGET_LINK_LIBRARIES(ab ${APR_LIBRARIES})
ENDIF()
GET_PROPERTY(tmp_includes TARGET ab PROPERTY INCLUDE_DIRECTORIES)

# getting duplicate manifest error with ApacheMonitor
# ADD_EXECUTABLE(ApacheMonitor support/win32/ApacheMonitor.c support/win32/ApacheMonitor.rc)
# SET(install_targets ${install_targets} ApacheMonitor)
# SET_TARGET_PROPERTIES(ApacheMonitor PROPERTIES WIN32_EXECUTABLE TRUE)
# TARGET_LINK_LIBRARIES(ApacheMonitor ${HTTPD_SYSTEM_LIBS} comctl32 wtsapi32)

ADD_EXECUTABLE(htcacheclean support/htcacheclean.c)
SET(install_targets ${install_targets} htcacheclean)
TARGET_LINK_LIBRARIES(htcacheclean ${APR_LIBRARIES})

ADD_EXECUTABLE(htdbm support/htdbm.c support/passwd_common.c)
SET(install_targets ${install_targets} htdbm)
TARGET_LINK_LIBRARIES(htdbm ${APR_LIBRARIES})

ADD_EXECUTABLE(htdigest support/htdigest.c)
SET(install_targets ${install_targets} htdigest)
TARGET_LINK_LIBRARIES(htdigest ${APR_LIBRARIES})

ADD_EXECUTABLE(htpasswd support/htpasswd.c support/passwd_common.c)
SET(install_targets ${install_targets} htpasswd)
TARGET_LINK_LIBRARIES(htpasswd ${APR_LIBRARIES})

ADD_EXECUTABLE(logresolve support/logresolve.c)
SET(install_targets ${install_targets} logresolve)
TARGET_LINK_LIBRARIES(logresolve ${APR_LIBRARIES})

ADD_EXECUTABLE(rotatelogs support/rotatelogs.c)
SET(install_targets ${install_targets} rotatelogs)
TARGET_LINK_LIBRARIES(rotatelogs ${APR_LIBRARIES})

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
INSTALL(DIRECTORY include/ DESTINATION include
    FILES_MATCHING PATTERN "*.h"
)
INSTALL(FILES ${other_installed_h} DESTINATION include)

INSTALL(DIRECTORY docs/manual/ DESTINATION manual)
INSTALL(DIRECTORY DESTINATION logs)
INSTALL(DIRECTORY DESTINATION cgi-bin)

INSTALL(CODE "EXECUTE_PROCESS(COMMAND perl ${CMAKE_CURRENT_SOURCE_DIR}/build/cpR_noreplace.pl ${CMAKE_CURRENT_SOURCE_DIR}/docs/error ${CMAKE_INSTALL_PREFIX}/error ifdestmissing)")

INSTALL(CODE "EXECUTE_PROCESS(COMMAND perl ${CMAKE_CURRENT_SOURCE_DIR}/build/cpR_noreplace.pl ${CMAKE_CURRENT_SOURCE_DIR}/docs/docroot ${CMAKE_INSTALL_PREFIX}/htdocs ifdestmissing)")

INSTALL(CODE "EXECUTE_PROCESS(COMMAND perl ${CMAKE_CURRENT_SOURCE_DIR}/build/cpR_noreplace.pl ${CMAKE_CURRENT_SOURCE_DIR}/docs/icons ${CMAKE_INSTALL_PREFIX}/icons ifdestmissing)")

# Copy generated .conf files from the build directory to the install,
# without overwriting stuff already there.
INSTALL(CODE "EXECUTE_PROCESS(COMMAND perl ${CMAKE_CURRENT_SOURCE_DIR}/build/cpR_noreplace.pl ${CMAKE_BINARY_DIR}/conf ${CMAKE_INSTALL_PREFIX}/conf)")
# But conf/original is supposed to be overwritten.
# Note: FILE(TO_NATIVE_PATH ...) leaves the backslashes unescaped, which
#       generates warnings.  Just do it manually since this build only supports
#       Windows anyway.
STRING(REPLACE "/" "\\\\" native_src ${CMAKE_BINARY_DIR}/conf/original)
STRING(REPLACE "/" "\\\\" native_dest ${CMAKE_INSTALL_PREFIX}/conf/original)
INSTALL(CODE "EXECUTE_PROCESS(COMMAND xcopy ${native_src} ${native_dest} /Q /S /Y)")

STRING(TOUPPER "${CMAKE_BUILD_TYPE}" buildtype)
MESSAGE(STATUS "")
MESSAGE(STATUS "")
MESSAGE(STATUS "Apache httpd configuration summary:")
MESSAGE(STATUS "")
MESSAGE(STATUS "  Build type ...................... : ${CMAKE_BUILD_TYPE}")
MESSAGE(STATUS "  Install prefix .................. : ${CMAKE_INSTALL_PREFIX}")
MESSAGE(STATUS "  C compiler ...................... : ${CMAKE_C_COMPILER}")
MESSAGE(STATUS "  APR include directory ........... : ${APR_INCLUDE_DIR}")
MESSAGE(STATUS "  APR libraries ................... : ${APR_LIBRARIES}")
MESSAGE(STATUS "  PCRE include directory .......... : ${PCRE_INCLUDE_DIR}")
MESSAGE(STATUS "  PCRE libraries .................. : ${PCRE_LIBRARIES}")
MESSAGE(STATUS "  libxml2 iconv prereq include dir. : ${LIBXML2_ICONV_INCLUDE_DIR}")
MESSAGE(STATUS "  libxml2 iconv prereq libraries .. : ${LIBXML2_ICONV_LIBRARIES}")
MESSAGE(STATUS "  Extra include directories ....... : ${EXTRA_INCLUDE_DIRS}")

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
