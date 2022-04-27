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

dnl
dnl APACHE_CHECK_CURL
dnl
dnl Configure for libcurl, giving preference to
dnl "--with-curl=<path>" if it was specified.
dnl
AC_DEFUN([APACHE_CHECK_CURL],[
  AC_CACHE_CHECK([for curl], [ac_cv_curl], [
    dnl initialise the variables we use
    ac_cv_curl=no
    ap_curl_found=""
    ap_curl_base=""
    ap_curl_libs=""

    dnl Determine the curl base directory, if any
    AC_MSG_CHECKING([for user-provided curl base directory])
    AC_ARG_WITH(curl, APACHE_HELP_STRING(--with-curl=PATH, curl installation directory), [
      dnl If --with-curl specifies a directory, we use that directory
      if test "x$withval" != "xyes" -a "x$withval" != "x"; then
        dnl This ensures $withval is actually a directory and that it is absolute
        ap_curl_base="`cd $withval ; pwd`"
      fi
    ])
    if test "x$ap_curl_base" = "x"; then
      AC_MSG_RESULT(none)
    else
      AC_MSG_RESULT($ap_curl_base)
    fi

    dnl Run header and version checks
    saved_CPPFLAGS="$CPPFLAGS"
    saved_LIBS="$LIBS"
    saved_LDFLAGS="$LDFLAGS"

    dnl Before doing anything else, load in pkg-config variables
    if test -n "$PKGCONFIG"; then
      saved_PKG_CONFIG_PATH="$PKG_CONFIG_PATH"
      AC_MSG_CHECKING([for pkg-config along $PKG_CONFIG_PATH])
      if test "x$ap_curl_base" != "x" ; then
        if test -f "${ap_curl_base}/lib/pkgconfig/libcurl.pc"; then
          dnl Ensure that the given path is used by pkg-config too, otherwise
          dnl the system libcurl.pc might be picked up instead.
          PKG_CONFIG_PATH="${ap_curl_base}/lib/pkgconfig${PKG_CONFIG_PATH+:}${PKG_CONFIG_PATH}"
          export PKG_CONFIG_PATH
        elif test -f "${ap_curl_base}/lib64/pkgconfig/libcurl.pc"; then
          dnl Ensure that the given path is used by pkg-config too, otherwise
          dnl the system libcurl.pc might be picked up instead.
          PKG_CONFIG_PATH="${ap_curl_base}/lib64/pkgconfig${PKG_CONFIG_PATH+:}${PKG_CONFIG_PATH}"
          export PKG_CONFIG_PATH
        fi
      fi
      AC_ARG_ENABLE(curl-staticlib-deps,APACHE_HELP_STRING(--enable-curl-staticlib-deps,[link mod_md with dependencies of libcurl's static libraries (as indicated by "pkg-config --static"). Must be specified in addition to --enable-md.]), [
        if test "$enableval" = "yes"; then
          PKGCONFIG_LIBOPTS="--static"
        fi
      ])
      ap_curl_libs="`$PKGCONFIG $PKGCONFIG_LIBOPTS --libs-only-l --silence-errors libcurl`"
      if test $? -eq 0; then
        ap_curl_found="yes"
        pkglookup="`$PKGCONFIG --cflags-only-I libcurl`"
        APR_ADDTO(CPPFLAGS, [$pkglookup])
        APR_ADDTO(MOD_CFLAGS, [$pkglookup])
        pkglookup="`$PKGCONFIG $PKGCONFIG_LIBOPTS --libs-only-L libcurl`"
        APR_ADDTO(LDFLAGS, [$pkglookup])
        APR_ADDTO(MOD_LDFLAGS, [$pkglookup])
        pkglookup="`$PKGCONFIG $PKGCONFIG_LIBOPTS --libs-only-other libcurl`"
        APR_ADDTO(LDFLAGS, [$pkglookup])
        APR_ADDTO(MOD_LDFLAGS, [$pkglookup])
      fi
      PKG_CONFIG_PATH="$saved_PKG_CONFIG_PATH"
    fi

    dnl fall back to the user-supplied directory if not found via pkg-config
    if test "x$ap_curl_base" != "x" -a "x$ap_curl_found" = "x"; then
      APR_ADDTO(CPPFLAGS, [-I$ap_curl_base/include])
      APR_ADDTO(MOD_CFLAGS, [-I$ap_curl_base/include])
      APR_ADDTO(LDFLAGS, [-L$ap_curl_base/lib])
      APR_ADDTO(MOD_LDFLAGS, [-L$ap_curl_base/lib])
      if test "x$ap_platform_runtime_link_flag" != "x"; then
        APR_ADDTO(LDFLAGS, [$ap_platform_runtime_link_flag$ap_curl_base/lib])
        APR_ADDTO(MOD_LDFLAGS, [$ap_platform_runtime_link_flag$ap_curl_base/lib])
      fi
    fi

    AC_CHECK_HEADERS([curl/curl.h])

    AC_MSG_CHECKING([for curl version >= 7.29])
    AC_TRY_COMPILE([#include <curl/curlver.h>],[
#if !defined(LIBCURL_VERSION_MAJOR)
#error "Missing libcurl version"
#endif
#if LIBCURL_VERSION_MAJOR < 7
#error "Unsupported libcurl version " LIBCURL_VERSION
#endif
#if LIBCURL_VERSION_MAJOR == 7 && LIBCURL_VERSION_MINOR < 29
#error "Unsupported libcurl version " LIBCURL_VERSION
#endif],
      [AC_MSG_RESULT(OK)
       ac_cv_curl=yes],
      [AC_MSG_RESULT(FAILED)])

    if test "x$ac_cv_curl" = "xyes"; then
      ap_curl_libs="${ap_curl_libs:--lcurl} `$apr_config --libs`"
      APR_ADDTO(MOD_LDFLAGS, [$ap_curl_libs])
      APR_ADDTO(LIBS, [$ap_curl_libs])
    fi

    dnl restore
    CPPFLAGS="$saved_CPPFLAGS"
    LIBS="$saved_LIBS"
    LDFLAGS="$saved_LDFLAGS"
  ])
  if test "x$ac_cv_curl" = "xyes"; then
    AC_DEFINE(HAVE_CURL, 1, [Define if curl is available])
  fi
])


dnl
dnl APACHE_CHECK_JANSSON
dnl
dnl Configure for libjansson, giving preference to
dnl "--with-jansson=<path>" if it was specified.
dnl
AC_DEFUN([APACHE_CHECK_JANSSON],[
  AC_CACHE_CHECK([for jansson], [ac_cv_jansson], [
    dnl initialise the variables we use
    ac_cv_jansson=no
    ap_jansson_found=""
    ap_jansson_base=""
    ap_jansson_libs=""

    dnl Determine the jansson base directory, if any
    AC_MSG_CHECKING([for user-provided jansson base directory])
    AC_ARG_WITH(jansson, APACHE_HELP_STRING(--with-jansson=PATH, jansson installation directory), [
      dnl If --with-jansson specifies a directory, we use that directory
      if test "x$withval" != "xyes" -a "x$withval" != "x"; then
        dnl This ensures $withval is actually a directory and that it is absolute
        ap_jansson_base="`cd $withval ; pwd`"
      fi
    ])
    if test "x$ap_jansson_base" = "x"; then
      AC_MSG_RESULT(none)
    else
      AC_MSG_RESULT($ap_jansson_base)
    fi

    dnl Run header and version checks
    saved_CPPFLAGS="$CPPFLAGS"
    saved_LIBS="$LIBS"
    saved_LDFLAGS="$LDFLAGS"

    dnl Before doing anything else, load in pkg-config variables
    if test -n "$PKGCONFIG"; then
      saved_PKG_CONFIG_PATH="$PKG_CONFIG_PATH"
      AC_MSG_CHECKING([for pkg-config along $PKG_CONFIG_PATH])
      if test "x$ap_jansson_base" != "x" ; then
        if test -f "${ap_jansson_base}/lib/pkgconfig/libjansson.pc"; then
          dnl Ensure that the given path is used by pkg-config too, otherwise
          dnl the system libjansson.pc might be picked up instead.
          PKG_CONFIG_PATH="${ap_jansson_base}/lib/pkgconfig${PKG_CONFIG_PATH+:}${PKG_CONFIG_PATH}"
          export PKG_CONFIG_PATH
        elif test -f "${ap_jansson_base}/lib64/pkgconfig/libjansson.pc"; then
          dnl Ensure that the given path is used by pkg-config too, otherwise
          dnl the system libjansson.pc might be picked up instead.
          PKG_CONFIG_PATH="${ap_jansson_base}/lib64/pkgconfig${PKG_CONFIG_PATH+:}${PKG_CONFIG_PATH}"
          export PKG_CONFIG_PATH
        fi
      fi
      AC_ARG_ENABLE(jansson-staticlib-deps,APACHE_HELP_STRING(--enable-jansson-staticlib-deps,[link mod_md with dependencies of libjansson's static libraries (as indicated by "pkg-config --static"). Must be specified in addition to --enable-md.]), [
        if test "$enableval" = "yes"; then
          PKGCONFIG_LIBOPTS="--static"
        fi
      ])
      ap_jansson_libs="`$PKGCONFIG $PKGCONFIG_LIBOPTS --libs-only-l --silence-errors libjansson`"
      if test $? -eq 0; then
        ap_jansson_found="yes"
        pkglookup="`$PKGCONFIG --cflags-only-I libjansson`"
        APR_ADDTO(CPPFLAGS, [$pkglookup])
        APR_ADDTO(MOD_CFLAGS, [$pkglookup])
        pkglookup="`$PKGCONFIG $PKGCONFIG_LIBOPTS --libs-only-L libjansson`"
        APR_ADDTO(LDFLAGS, [$pkglookup])
        APR_ADDTO(MOD_LDFLAGS, [$pkglookup])
        pkglookup="`$PKGCONFIG $PKGCONFIG_LIBOPTS --libs-only-other libjansson`"
        APR_ADDTO(LDFLAGS, [$pkglookup])
        APR_ADDTO(MOD_LDFLAGS, [$pkglookup])
      fi
      PKG_CONFIG_PATH="$saved_PKG_CONFIG_PATH"
    fi

    dnl fall back to the user-supplied directory if not found via pkg-config
    if test "x$ap_jansson_base" != "x" -a "x$ap_jansson_found" = "x"; then
      APR_ADDTO(CPPFLAGS, [-I$ap_jansson_base/include])
      APR_ADDTO(MOD_CFLAGS, [-I$ap_jansson_base/include])
      APR_ADDTO(LDFLAGS, [-L$ap_jansson_base/lib])
      APR_ADDTO(MOD_LDFLAGS, [-L$ap_jansson_base/lib])
      if test "x$ap_platform_runtime_link_flag" != "x"; then
        APR_ADDTO(LDFLAGS, [$ap_platform_runtime_link_flag$ap_jansson_base/lib])
        APR_ADDTO(MOD_LDFLAGS, [$ap_platform_runtime_link_flag$ap_jansson_base/lib])
      fi
    fi

    # attempts to include jansson.h fail me. So lets make sure we can at least
    # include its other header file
    AC_TRY_COMPILE([#include <jansson_config.h>],[],
      [AC_MSG_RESULT(OK) 
       ac_cv_jansson=yes], 
       [AC_MSG_RESULT(FAILED)])

    if test "x$ac_cv_jansson" = "xyes"; then
      ap_jansson_libs="${ap_jansson_libs:--ljansson} `$apr_config --libs`"
      APR_ADDTO(MOD_LDFLAGS, [$ap_jansson_libs])
      APR_ADDTO(LIBS, [$ap_jansson_libs])
    fi

    dnl restore
    CPPFLAGS="$saved_CPPFLAGS"
    LIBS="$saved_LIBS"
    LDFLAGS="$saved_LDFLAGS"
  ])
  if test "x$ac_cv_jansson" = "xyes"; then
    AC_DEFINE(HAVE_JANSSON, 1, [Define if jansson is available])
  fi
])


dnl #  start of module specific part
APACHE_MODPATH_INIT(md)

dnl #  list of module object files
md_objs="dnl
md_acme.lo dnl
md_acme_acct.lo dnl
md_acme_authz.lo dnl
md_acme_drive.lo dnl
md_acmev2_drive.lo dnl
md_acme_order.lo dnl
md_core.lo dnl
md_curl.lo dnl
md_crypt.lo dnl
md_event.lo dnl
md_http.lo dnl
md_json.lo dnl
md_jws.lo dnl
md_log.lo dnl
md_ocsp.lo dnl
md_result.lo dnl
md_reg.lo dnl
md_status.lo dnl
md_store.lo dnl
md_store_fs.lo dnl
md_tailscale.lo dnl
md_time.lo dnl
md_util.lo dnl
mod_md.lo dnl
mod_md_config.lo dnl
mod_md_drive.lo dnl
mod_md_ocsp.lo dnl
mod_md_os.lo dnl
mod_md_status.lo dnl
"

# Ensure that other modules can pick up mod_md.h
APR_ADDTO(INCLUDES, [-I\$(top_srcdir)/$modpath_current])

dnl # hook module into the Autoconf mechanism (--enable-md)
APACHE_MODULE(md, [Managed Domain handling], $md_objs, , most, [
    APACHE_CHECK_OPENSSL
    if test "x$ac_cv_openssl" = "xno" ; then
        AC_MSG_WARN([libssl (or compatible) not found])
        enable_md=no
    fi
    
    APACHE_CHECK_JANSSON
    if test "x$ac_cv_jansson" != "xyes" ; then
        AC_MSG_WARN([libjansson not found])
        enable_md=no
    fi

    APACHE_CHECK_CURL
    if test "x$ac_cv_curl" != "xyes" ; then
        AC_MSG_WARN([libcurl not found])
        enable_md=no
    fi
    
    AC_CHECK_FUNCS([arc4random_buf], 
        [APR_ADDTO(MOD_CPPFLAGS, ["-DMD_HAVE_ARC4RANDOM"])], [])

    if test "x$enable_md" = "xshared"; then
       APR_ADDTO(MOD_MD_LDADD, [-export-symbols-regex md_module])
    fi
])

dnl #  end of module specific part
APACHE_MODPATH_FINISH

