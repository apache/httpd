dnl Licensed to the Apache Software Foundation (ASF) under one or more
dnl contributor license agreements.  See the NOTICE file distributed with
dnl this work for additional information regarding copyright ownership.
dnl The ASF licenses this file to You under the Apache License, Version 2.0
dnl (the "License"); you may not use this file except in compliance with
dnl the License.  You may obtain a copy of the License at
dnl
dnl      http://www.apache.org/licenses/LICENSE-2.0
dnl
dnl Unless required by applicable law or agreed to in writing, software
dnl distributed under the License is distributed on an "AS IS" BASIS,
dnl WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
dnl See the License for the specific language governing permissions and
dnl limitations under the License.

dnl #  start of module specific part
APACHE_MODPATH_INIT(http2)

dnl #  list of module object files
http2_objs="dnl
mod_http2.lo dnl
h2_bucket_beam.lo dnl
h2_bucket_eos.lo dnl
h2_c1.lo dnl
h2_c1_io.lo dnl
h2_c2.lo dnl
h2_c2_filter.lo dnl
h2_config.lo dnl
h2_conn_ctx.lo dnl
h2_headers.lo dnl
h2_mplx.lo dnl
h2_protocol.lo dnl
h2_push.lo dnl
h2_request.lo dnl
h2_session.lo dnl
h2_stream.lo dnl
h2_switch.lo dnl
h2_util.lo dnl
h2_workers.lo dnl
h2_ws.lo dnl
"

dnl
dnl APACHE_CHECK_NGHTTP2
dnl
dnl Configure for nghttp2, giving preference to
dnl "--with-nghttp2=<path>" if it was specified.
dnl
AC_DEFUN([APACHE_CHECK_NGHTTP2],[
  AC_CACHE_CHECK([for nghttp2], [ac_cv_nghttp2], [
    dnl initialise the variables we use
    ac_cv_nghttp2=no
    ap_nghttp2_found=""
    ap_nghttp2_base=""
    ap_nghttp2_libs=""

    dnl Determine the nghttp2 base directory, if any
    AC_MSG_CHECKING([for user-provided nghttp2 base directory])
    AC_ARG_WITH(nghttp2, APACHE_HELP_STRING(--with-nghttp2=PATH, nghttp2 installation directory), [
      dnl If --with-nghttp2 specifies a directory, we use that directory
      if test "x$withval" != "xyes" -a "x$withval" != "x"; then
        dnl This ensures $withval is actually a directory and that it is absolute
        ap_nghttp2_base="`cd $withval ; pwd`"
      fi
    ])
    if test "x$ap_nghttp2_base" = "x"; then
      AC_MSG_RESULT(none)
    else
      AC_MSG_RESULT($ap_nghttp2_base)
    fi

    dnl Run header and version checks
    saved_CPPFLAGS="$CPPFLAGS"
    saved_LIBS="$LIBS"
    saved_LDFLAGS="$LDFLAGS"

    dnl Before doing anything else, load in pkg-config variables
    if test -n "$PKGCONFIG"; then
      saved_PKG_CONFIG_PATH="$PKG_CONFIG_PATH"
      AC_MSG_CHECKING([for pkg-config along $PKG_CONFIG_PATH])
      if test "x$ap_nghttp2_base" != "x" ; then
        if test -f "${ap_nghttp2_base}/lib/pkgconfig/libnghttp2.pc"; then
          dnl Ensure that the given path is used by pkg-config too, otherwise
          dnl the system libnghttp2.pc might be picked up instead.
          PKG_CONFIG_PATH="${ap_nghttp2_base}/lib/pkgconfig${PKG_CONFIG_PATH+:}${PKG_CONFIG_PATH}"
          export PKG_CONFIG_PATH
        elif test -f "${ap_nghttp2_base}/lib64/pkgconfig/libnghttp2.pc"; then
          dnl Ensure that the given path is used by pkg-config too, otherwise
          dnl the system libnghttp2.pc might be picked up instead.
          PKG_CONFIG_PATH="${ap_nghttp2_base}/lib64/pkgconfig${PKG_CONFIG_PATH+:}${PKG_CONFIG_PATH}"
          export PKG_CONFIG_PATH
        fi
      fi
      AC_ARG_ENABLE(nghttp2-staticlib-deps,APACHE_HELP_STRING(--enable-nghttp2-staticlib-deps,[link mod_http2 with dependencies of libnghttp2's static libraries (as indicated by "pkg-config --static"). Must be specified in addition to --enable-http2.]), [
        if test "$enableval" = "yes"; then
          PKGCONFIG_LIBOPTS="--static"
        fi
      ])
      ap_nghttp2_libs="`$PKGCONFIG $PKGCONFIG_LIBOPTS --libs-only-l --silence-errors libnghttp2`"
      if test $? -eq 0; then
        ap_nghttp2_found="yes"
        pkglookup="`$PKGCONFIG --cflags-only-I libnghttp2`"
        APR_ADDTO(CPPFLAGS, [$pkglookup])
        APR_ADDTO(MOD_CFLAGS, [$pkglookup])
        pkglookup="`$PKGCONFIG $PKGCONFIG_LIBOPTS --libs-only-L libnghttp2`"
        APR_ADDTO(LDFLAGS, [$pkglookup])
        APR_ADDTO(MOD_LDFLAGS, [$pkglookup])
        pkglookup="`$PKGCONFIG $PKGCONFIG_LIBOPTS --libs-only-other libnghttp2`"
        APR_ADDTO(LDFLAGS, [$pkglookup])
        APR_ADDTO(MOD_LDFLAGS, [$pkglookup])
      fi
      PKG_CONFIG_PATH="$saved_PKG_CONFIG_PATH"
    fi

    dnl fall back to the user-supplied directory if not found via pkg-config
    if test "x$ap_nghttp2_base" != "x" -a "x$ap_nghttp2_found" = "x"; then
      APR_ADDTO(CPPFLAGS, [-I$ap_nghttp2_base/include])
      APR_ADDTO(MOD_CFLAGS, [-I$ap_nghttp2_base/include])
      APR_ADDTO(LDFLAGS, [-L$ap_nghttp2_base/lib])
      APR_ADDTO(MOD_LDFLAGS, [-L$ap_nghttp2_base/lib])
      if test "x$ap_platform_runtime_link_flag" != "x"; then
        APR_ADDTO(LDFLAGS, [$ap_platform_runtime_link_flag$ap_nghttp2_base/lib])
        APR_ADDTO(MOD_LDFLAGS, [$ap_platform_runtime_link_flag$ap_nghttp2_base/lib])
      fi
    fi

    AC_MSG_CHECKING([for nghttp2 version >= 1.2.1])
    AC_TRY_COMPILE([#include <nghttp2/nghttp2ver.h>],[
#if !defined(NGHTTP2_VERSION_NUM)
#error "Missing nghttp2 version"
#endif
#if NGHTTP2_VERSION_NUM < 0x010201
#error "Unsupported nghttp2 version " NGHTTP2_VERSION_TEXT
#endif],
      [AC_MSG_RESULT(OK)
       ac_cv_nghttp2=yes],
      [AC_MSG_RESULT(FAILED)])

    if test "x$ac_cv_nghttp2" = "xyes"; then
      ap_nghttp2_libs="${ap_nghttp2_libs:--lnghttp2} `$apr_config --libs`"
      APR_ADDTO(MOD_LDFLAGS, [$ap_nghttp2_libs])
      APR_ADDTO(LIBS, [$ap_nghttp2_libs])

      dnl Run library and function checks
      liberrors=""
      AC_CHECK_HEADERS([nghttp2/nghttp2.h])
      AC_CHECK_FUNCS([nghttp2_session_server_new2], [], [liberrors="yes"])
      if test "x$liberrors" != "x"; then
        AC_MSG_WARN([nghttp2 library is unusable])
      fi
dnl # nghttp2 >= 1.3.0: access to stream weights
      AC_CHECK_FUNCS([nghttp2_stream_get_weight], [], [liberrors="yes"])
      if test "x$liberrors" != "x"; then
        AC_MSG_WARN([nghttp2 version >= 1.3.0 is required])
      fi
dnl # nghttp2 >= 1.5.0: changing stream priorities
      AC_CHECK_FUNCS([nghttp2_session_change_stream_priority], 
        [APR_ADDTO(MOD_CPPFLAGS, ["-DH2_NG2_CHANGE_PRIO"])], [])
dnl # nghttp2 >= 1.14.0: invalid header callback
      AC_CHECK_FUNCS([nghttp2_session_callbacks_set_on_invalid_header_callback], 
        [APR_ADDTO(MOD_CPPFLAGS, ["-DH2_NG2_INVALID_HEADER_CB"])], [])
dnl # nghttp2 >= 1.15.0: get/set stream window sizes
      AC_CHECK_FUNCS([nghttp2_session_get_stream_local_window_size], 
        [APR_ADDTO(MOD_CPPFLAGS, ["-DH2_NG2_LOCAL_WIN_SIZE"])], [])
dnl # nghttp2 >= 1.15.0: don't keep info on closed streams
      AC_CHECK_FUNCS([nghttp2_option_set_no_closed_streams],
        [APR_ADDTO(MOD_CPPFLAGS, ["-DH2_NG2_NO_CLOSED_STREAMS"])], [])
dnl # nghttp2 >= 1.50.0: rfc9113 leading/trailing whitespec strictness
      AC_CHECK_FUNCS([nghttp2_option_set_no_rfc9113_leading_and_trailing_ws_validation],
        [APR_ADDTO(MOD_CPPFLAGS, ["-DH2_NG2_RFC9113_STRICTNESS"])], [])
    else
      AC_MSG_WARN([nghttp2 version is too old])
    fi

    dnl restore
    CPPFLAGS="$saved_CPPFLAGS"
    LIBS="$saved_LIBS"
    LDFLAGS="$saved_LDFLAGS"
  ])
  if test "x$ac_cv_nghttp2" = "xyes"; then
    AC_DEFINE(HAVE_NGHTTP2, 1, [Define if nghttp2 is available])
  fi
])


dnl # hook module into the Autoconf mechanism (--enable-http2)
APACHE_MODULE(http2, [HTTP/2 protocol handling in addition to HTTP protocol 
handling. Implemented by mod_http2. This module requires a libnghttp2 installation. 
See --with-nghttp2 on how to manage non-standard locations. This module
is usually linked shared and requires loading. ], $http2_objs, , most, [
    APACHE_CHECK_OPENSSL
    if test "$ac_cv_openssl" = "yes" ; then
        APR_ADDTO(MOD_CPPFLAGS, ["-DH2_OPENSSL"])
    fi

    APACHE_CHECK_NGHTTP2
    if test "$ac_cv_nghttp2" = "yes" ; then
        if test "x$enable_http2" = "xshared"; then
           # The only symbol which needs to be exported is the module
           # structure, so ask libtool to hide everything else:
           APR_ADDTO(MOD_HTTP2_LDADD, [-export-symbols-regex http2_module])
        fi
    else
        enable_http2=no
    fi
])

# Ensure that other modules can pick up mod_http2.h
# icing: hold back for now until it is more stable
#APR_ADDTO(INCLUDES, [-I\$(top_srcdir)/$modpath_current])



dnl #  list of module object files
proxy_http2_objs="dnl
mod_proxy_http2.lo dnl
h2_proxy_session.lo dnl
h2_proxy_util.lo dnl
"

dnl # hook module into the Autoconf mechanism (--enable-proxy_http2)
APACHE_MODULE(proxy_http2, [HTTP/2 proxy module. This module requires a libnghttp2 installation. 
See --with-nghttp2 on how to manage non-standard locations. Also requires --enable-proxy.], $proxy_http2_objs, , no, [
    APACHE_CHECK_NGHTTP2
    if test "$ac_cv_nghttp2" = "yes" ; then
        if test "x$enable_http2" = "xshared"; then
           # The only symbol which needs to be exported is the module
           # structure, so ask libtool to hide everything else:
           APR_ADDTO(MOD_PROXY_HTTP2_LDADD, [-export-symbols-regex proxy_http2_module])
        fi
    else
        enable_proxy_http2=no
    fi
], proxy)


dnl #  end of module specific part
APACHE_MODPATH_FINISH

