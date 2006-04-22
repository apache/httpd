dnl  Copyright 2001-2005 The Apache Software Foundation or its licensors, as
dnl  applicable.
dnl  Licensed under the Apache License, Version 2.0 (the "License");
dnl  you may not use this file except in compliance with the License.
dnl  You may obtain a copy of the License at
dnl 
dnl       http://www.apache.org/licenses/LICENSE-2.0
dnl 
dnl  Unless required by applicable law or agreed to in writing, software
dnl  distributed under the License is distributed on an "AS IS" BASIS,
dnl  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
dnl  See the License for the specific language governing permissions and
dnl  limitations under the License.

AC_DEFUN([CHECK_DISTCACHE], [
  AC_MSG_CHECKING(whether Distcache is required)
  ap_ssltk_dc="no"
  tmp_nomessage=""
  tmp_forced="no"
  AC_ARG_ENABLE(distcache,
    APACHE_HELP_STRING(--enable-distcache,Select distcache support in mod_ssl),
    ap_ssltk_dc="$enableval"
    tmp_nomessage=""
    tmp_forced="yes"
    if test "x$ap_ssltk_dc" = "x"; then
      ap_ssltk_dc="yes"
      dnl our "error"s become "tests revealed that..."
      tmp_forced="no"
    fi
    if test "$ap_ssltk_dc" != "yes" -a "$ap_ssltk_dc" != "no"; then
      tmp_nomessage="--enable-distcache had illegal syntax - disabling"
      ap_ssltk_dc="no"
    fi)
  if test "$tmp_forced" = "no"; then
    AC_MSG_RESULT($ap_ssltk_dc (default))
  else
    AC_MSG_RESULT($ap_ssltk_dc (specified))
  fi
  if test "$tmp_forced" = "yes" -a "x$ap_ssltk_dc" = "xno" -a "x$tmp_nomessage" != "x"; then
    AC_MSG_ERROR(distcache support failed: $tmp_nomessage)
  fi
  if test "$ap_ssltk_dc" = "yes"; then
    AC_CHECK_HEADER(
      [distcache/dc_client.h],
      [],
      [tmp_nomessage="can't include distcache headers"
      ap_ssltk_dc="no"])
    if test "$tmp_forced" = "yes" -a "x$ap_ssltk_dc" = "xno"; then
      AC_MSG_ERROR(distcache support failed: $tmp_nomessage)
    fi
  fi
  if test "$ap_ssltk_dc" = "yes"; then
    AC_MSG_CHECKING(for Distcache version)
    AC_TRY_COMPILE(
[#include <distcache/dc_client.h>],
[#if DISTCACHE_CLIENT_API != 0x0001
#error "distcache API version is unrecognised"
#endif],
[],
[tmp_nomessage="distcache has an unsupported API version"
ap_ssltk_dc="no"])
    AC_MSG_RESULT($ap_ssltk_dc)
    if test "$tmp_forced" = "yes" -a "x$ap_ssltk_dc" = "xno"; then
      AC_MSG_ERROR(distcache support failed: $tmp_nomessage)
    fi
  fi
  if test "$ap_ssltk_dc" = "yes"; then
    AC_MSG_CHECKING(for Distcache libraries)
    save_libs=$LIBS
    LIBS="$LIBS -ldistcache -lnal"
    AC_TRY_LINK(
      [#include <distcache/dc_client.h>],
      [DC_CTX *foo = DC_CTX_new((const char *)0,0);],
      [],
      [tmp_no_message="failed to link with distcache libraries"
      ap_ssltk_dc="no"])
    LIBS=$save_libs
    AC_MSG_RESULT($ap_ssltk_dc)
    if test "$tmp_forced" = "yes" -a "x$ap_ssltk_dc" = "xno"; then
      AC_MSG_ERROR(distcache support failed: $tmp_nomessage)
    else
      APR_ADDTO(MOD_SSL_LDADD, [-ldistcache -lnal])
      AC_DEFINE(HAVE_DISTCACHE, 1, [Define if distcache support is enabled])
    fi
  fi
])

dnl #  start of module specific part
APACHE_MODPATH_INIT(ssl)

dnl #  list of module object files
ssl_objs="dnl
mod_ssl.lo dnl
ssl_engine_config.lo dnl
ssl_engine_dh.lo dnl
ssl_engine_init.lo dnl
ssl_engine_io.lo dnl
ssl_engine_kernel.lo dnl
ssl_engine_log.lo dnl
ssl_engine_mutex.lo dnl
ssl_engine_pphrase.lo dnl
ssl_engine_rand.lo dnl
ssl_engine_vars.lo dnl
ssl_expr.lo dnl
ssl_expr_eval.lo dnl
ssl_expr_parse.lo dnl
ssl_expr_scan.lo dnl
ssl_scache.lo dnl
ssl_scache_dbm.lo dnl
ssl_scache_shmcb.lo dnl
ssl_scache_dc.lo dnl
ssl_util.lo dnl
ssl_util_ssl.lo dnl
"
dnl #  hook module into the Autoconf mechanism (--enable-ssl option)
APACHE_MODULE(ssl, [SSL/TLS support (mod_ssl)], $ssl_objs, , no, [
    APACHE_CHECK_SSL_TOOLKIT
    APR_SETVAR(MOD_SSL_LDADD, [\$(SSL_LIBS)])
    CHECK_DISTCACHE
    if test "x$enable_ssl" = "xshared"; then
       # The only symbol which needs to be exported is the module
       # structure, so ask libtool to hide everything else:
       APR_ADDTO(MOD_SSL_LDADD, [-export-symbols-regex ssl_module])
    fi
])

# Ensure that other modules can pick up mod_ssl.h
APR_ADDTO(INCLUDES, [-I\$(top_srcdir)/$modpath_current])

dnl #  end of module specific part
APACHE_MODPATH_FINISH

