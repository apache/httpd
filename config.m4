dnl ## ====================================================================
dnl ## The Apache Software License, Version 1.1
dnl ##  
dnl ## Copyright (c) 2000-2002 The Apache Software Foundation.  All rights
dnl ## reserved.
dnl ##
dnl ## Redistribution and use in source and binary forms, with or without
dnl ## modification, are permitted provided that the following conditions
dnl ## are met:
dnl ##
dnl ## 1. Redistributions of source code must retain the above copyright
dnl ##    notice, this list of conditions and the following disclaimer.
dnl ##
dnl ## 2. Redistributions in binary form must reproduce the above copyright
dnl ##    notice, this list of conditions and the following disclaimer in
dnl ##    the documentation and/or other materials provided with the
dnl ##    distribution.
dnl ##
dnl ## 3. The end-user documentation included with the redistribution,
dnl ##    if any, must include the following acknowledgment:
dnl ##       "This product includes software developed by the
dnl ##        Apache Software Foundation (http://www.apache.org/)."
dnl ##    Alternately, this acknowledgment may appear in the software itself,
dnl ##    if and wherever such third-party acknowledgments normally appear.
dnl ##
dnl ## 4. The names "Apache" and "Apache Software Foundation" must
dnl ##    not be used to endorse or promote products derived from this
dnl ##    software without prior written permission. For written
dnl ##    permission, please contact apache@apache.org.
dnl ##
dnl ## 5. Products derived from this software may not be called "Apache",
dnl ##    nor may "Apache" appear in their name, without prior written
dnl ##    permission of the Apache Software Foundation.
dnl ##
dnl ## THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESSED OR IMPLIED
dnl ## WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
dnl ## OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
dnl ## DISCLAIMED.  IN NO EVENT SHALL THE APACHE SOFTWARE FOUNDATION OR
dnl ## ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
dnl ## SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
dnl ## LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
dnl ## USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
dnl ## ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
dnl ## OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
dnl ## OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
dnl ## SUCH DAMAGE.
dnl ## ====================================================================

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
      APR_ADDTO(LIBS,[-ldistcache -lnal])
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
    CHECK_DISTCACHE
])

dnl #  end of module specific part
APACHE_MODPATH_FINISH

