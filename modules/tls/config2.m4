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
APACHE_MODPATH_INIT(tls)

dnl #  list of module object files
tls_objs="dnl
mod_tls.lo dnl
tls_cache.lo dnl
tls_cert.lo dnl
tls_conf.lo dnl
tls_core.lo dnl
tls_filter.lo dnl
tls_ocsp.lo dnl
tls_proto.lo dnl
tls_util.lo dnl
tls_var.lo dnl
"

dnl
dnl APACHE_CHECK_TLS
dnl
dnl Configure for rustls, giving preference to
dnl "--with-rustls=<path>" if it was specified.
dnl
AC_DEFUN([APACHE_CHECK_RUSTLS],[
  AC_CACHE_CHECK([for rustls], [ac_cv_rustls], [
    dnl initialise the variables we use
    ac_cv_rustls=no
    ap_rustls_found=""
    ap_rustls_base=""
    ap_rustls_libs=""

    dnl Determine the rustls base directory, if any
    AC_MSG_CHECKING([for user-provided rustls base directory])
    AC_ARG_WITH(rustls, APACHE_HELP_STRING(--with-rustls=PATH, rustls installation directory), [
      dnl If --with-rustls specifies a directory, we use that directory
      if test "x$withval" != "xyes" -a "x$withval" != "x"; then
        dnl This ensures $withval is actually a directory and that it is absolute
        ap_rustls_base="`cd $withval ; pwd`"
      fi
    ])
    if test "x$ap_rustls_base" = "x"; then
      AC_MSG_RESULT(none)
    else
      AC_MSG_RESULT($ap_rustls_base)
    fi

    dnl Run header and version checks
    saved_CPPFLAGS="$CPPFLAGS"
    saved_LIBS="$LIBS"
    saved_LDFLAGS="$LDFLAGS"

    dnl Before doing anything else, load in pkg-config variables
    if test -n "$PKGCONFIG"; then
      saved_PKG_CONFIG_PATH="$PKG_CONFIG_PATH"
      AC_MSG_CHECKING([for pkg-config along $PKG_CONFIG_PATH])
      if test "x$ap_rustls_base" != "x" ; then
        if test -f "${ap_rustls_base}/lib/pkgconfig/librustls.pc"; then
          dnl Ensure that the given path is used by pkg-config too, otherwise
          dnl the system librustls.pc might be picked up instead.
          PKG_CONFIG_PATH="${ap_rustls_base}/lib/pkgconfig${PKG_CONFIG_PATH+:}${PKG_CONFIG_PATH}"
          export PKG_CONFIG_PATH
        elif test -f "${ap_rustls_base}/lib64/pkgconfig/librustls.pc"; then
          dnl Ensure that the given path is used by pkg-config too, otherwise
          dnl the system librustls.pc might be picked up instead.
          PKG_CONFIG_PATH="${ap_rustls_base}/lib64/pkgconfig${PKG_CONFIG_PATH+:}${PKG_CONFIG_PATH}"
          export PKG_CONFIG_PATH
        fi
      fi
      ap_rustls_libs="`$PKGCONFIG $PKGCONFIG_LIBOPTS --libs-only-l --silence-errors librustls`"
      if test $? -eq 0; then
        ap_rustls_found="yes"
        pkglookup="`$PKGCONFIG --cflags-only-I librustls`"
        APR_ADDTO(CPPFLAGS, [$pkglookup])
        APR_ADDTO(MOD_CFLAGS, [$pkglookup])
        pkglookup="`$PKGCONFIG $PKGCONFIG_LIBOPTS --libs-only-L librustls`"
        APR_ADDTO(LDFLAGS, [$pkglookup])
        APR_ADDTO(MOD_LDFLAGS, [$pkglookup])
        pkglookup="`$PKGCONFIG $PKGCONFIG_LIBOPTS --libs-only-other librustls`"
        APR_ADDTO(LDFLAGS, [$pkglookup])
        APR_ADDTO(MOD_LDFLAGS, [$pkglookup])
      fi
      PKG_CONFIG_PATH="$saved_PKG_CONFIG_PATH"
    fi

    dnl fall back to the user-supplied directory if not found via pkg-config
    if test "x$ap_rustls_base" != "x" -a "x$ap_rustls_found" = "x"; then
      APR_ADDTO(CPPFLAGS, [-I$ap_rustls_base/include])
      APR_ADDTO(MOD_CFLAGS, [-I$ap_rustls_base/include])
      APR_ADDTO(LDFLAGS, [-L$ap_rustls_base/lib])
      APR_ADDTO(MOD_LDFLAGS, [-L$ap_rustls_base/lib])
      if test "x$ap_platform_runtime_link_flag" != "x"; then
        APR_ADDTO(LDFLAGS, [$ap_platform_runtime_link_flag$ap_rustls_base/lib])
        APR_ADDTO(MOD_LDFLAGS, [$ap_platform_runtime_link_flag$ap_rustls_base/lib])
      fi
    fi

    AC_MSG_CHECKING([for rustls version >= 0.9.2])
    AC_TRY_COMPILE([#include <rustls.h>],[
rustls_version();
rustls_acceptor_new();
],
      [AC_MSG_RESULT(OK)
       ac_cv_rustls=yes],
      [AC_MSG_RESULT(FAILED)])

    dnl restore
    CPPFLAGS="$saved_CPPFLAGS"
    LIBS="$saved_LIBS"
    LDFLAGS="$saved_LDFLAGS"
  ])
  if test "x$ac_cv_rustls" = "xyes"; then
    AC_DEFINE(HAVE_RUSTLS, 1, [Define if rustls is available])
  fi
])


dnl # hook module into the Autoconf mechanism (--enable-http2)
APACHE_MODULE(tls, [TLS protocol handling using rustls. Implemented by mod_tls.
This module requires a librustls installation.
See --with-rustls on how to manage non-standard locations. This module
is usually linked shared and requires loading. ], $tls_objs, , most, [
    APACHE_CHECK_RUSTLS
    if test "$ac_cv_rustls" = "yes" ; then
        if test "x$enable_tls" = "xshared"; then
           case `uname` in
             "Darwin")
                MOD_TLS_LINK_LIBS="-lrustls -framework Security -framework Foundation"
                ;;
             *)
                MOD_TLS_LINK_LIBS="-lrustls"
                ;;
           esac

           # Some rustls versions need an extra -lm when linked
           # See https://github.com/rustls/rustls-ffi/issues/133
           rustls_version=`rustc --version`
           case "$rustls_version" in
              *1.55*) need_lm="yes" ;;
              *1.56*) need_lm="yes" ;;
              *1.57*) need_lm="yes" ;;
           esac
           if test "$need_lm" = "yes" ; then
                MOD_TLS_LINK_LIBS="$MOD_TLS_LINK_LIBS -lm"
           fi

           # The only symbol which needs to be exported is the module
           # structure, so ask libtool to hide everything else:
           APR_ADDTO(MOD_TLS_LDADD, [$MOD_TLS_LINK_LIBS -export-symbols-regex tls_module])
        fi
    else
        enable_tls=no
    fi
])


dnl #  end of module specific part
APACHE_MODPATH_FINISH

