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

APACHE_MODPATH_INIT(wasm)

dnl #  list of module object files
wasm_objs="dnl
mod_wasm.lo
"

dnl
dnl APACHE_CHECK_WASMRUNTIME
dnl
dnl Configure for Wasm Runtime, giving preference to
dnl "--with-wasmruntime=<path>" if it was specified.
dnl
AC_DEFUN([APACHE_CHECK_WASMRUNTIME],[
  AC_CACHE_CHECK([for wasmruntime], [ac_cv_wasmruntime], [
    dnl initialise the variables we use
    ac_cv_wasmruntime=no
    ap_wasmruntime_found=""
    ap_wasmruntime_base=""
    ap_wasmruntime_libs=""

    dnl Determine the Wasm Runtime base directory, if any
    AC_MSG_CHECKING([for user-provided Wasm Runtime base directory])
    AC_ARG_WITH(
      wasmruntime,
      APACHE_HELP_STRING(--with-wasmruntime=PATH, Wasm Runtime installation directory),
      [
      dnl If --with-wasmruntime specifies a directory, we use that directory
      if test "x$withval" != "xyes" -a "x$withval" != "x"; then
        dnl This ensures $withval is actually a directory and that it is absolute
        ap_wasmruntime_base="`cd $withval ; pwd`"
      fi
    ])

    if test "x$ap_wasmruntime_base" = "x"; then
      AC_MSG_RESULT(none)
    else
      AC_MSG_RESULT()
    fi

    dnl Run header and version checks
    saved_CPPFLAGS="$CPPFLAGS"
    saved_LIBS="$LIBS"
    saved_LDFLAGS="$LDFLAGS"

    dnl Before doing anything else, load in pkg-config variables
    if test -n "$PKGCONFIG"; then
      saved_PKG_CONFIG_PATH="$PKG_CONFIG_PATH"
      AC_MSG_CHECKING([for pkg-config along $PKG_CONFIG_PATH])
      if test "x$ap_wasmruntime_base" != "x" ; then
        if test -f "${ap_wasmruntime_base}/lib/pkgconfig/libwasm_runtime.pc"; then
          dnl Ensure that the given path is used by pkg-config too, otherwise
          dnl the system libwasm_runtime.pc might be picked up instead.
          PKG_CONFIG_PATH="${ap_wasmruntime_base}/lib/pkgconfig${PKG_CONFIG_PATH+:}${PKG_CONFIG_PATH}"
          export PKG_CONFIG_PATH
        elif test -f "${ap_wasmruntime_base}/lib64/pkgconfig/libwasm_runtime.pc"; then
          dnl Ensure that the given path is used by pkg-config too, otherwise
          dnl the system libwasm_runtime.pc might be picked up instead.
          PKG_CONFIG_PATH="${ap_wasmruntime_base}/lib64/pkgconfig${PKG_CONFIG_PATH+:}${PKG_CONFIG_PATH}"
          export PKG_CONFIG_PATH
        fi
      fi
      ap_wasmruntime_libs="`$PKGCONFIG $PKGCONFIG_LIBOPTS --libs-only-l --silence-errors libwasm_runtime`"
      if test $? -eq 0; then
        ap_wasmruntime_found="yes"
        pkglookup="`$PKGCONFIG --cflags-only-I libwasm_runtime`"
        APR_ADDTO(CPPFLAGS, [$pkglookup])
        APR_ADDTO(MOD_CFLAGS, [$pkglookup])
        pkglookup="`$PKGCONFIG $PKGCONFIG_LIBOPTS --libs-only-L libwasm_runtime`"
        APR_ADDTO(LDFLAGS, [$pkglookup])
        APR_ADDTO(MOD_LDFLAGS, [$pkglookup])
        pkglookup="`$PKGCONFIG $PKGCONFIG_LIBOPTS --libs-only-other libwasm_runtime`"
        APR_ADDTO(LDFLAGS, [$pkglookup])
        APR_ADDTO(MOD_LDFLAGS, [$pkglookup])
      fi
      PKG_CONFIG_PATH="$saved_PKG_CONFIG_PATH"
    fi

    dnl fall back to the user-supplied directory if not found via pkg-config
    if test "x$ap_wasmruntime_base" != "x" -a "x$ap_wasmruntime_found" = "x"; then
      APR_ADDTO(CPPFLAGS, [-I$ap_wasmruntime_base/include])
      APR_ADDTO(MOD_CFLAGS, [-I$ap_wasmruntime_base/include])
      APR_ADDTO(LDFLAGS, [-L$ap_wasmruntime_base/target/release])
      APR_ADDTO(MOD_LDFLAGS, [-L$ap_wasmruntime_base/target/release])
      if test "x$ap_platform_runtime_link_flag" != "x"; then
        APR_ADDTO(LDFLAGS, [$ap_platform_runtime_link_flag$ap_wasmruntime_base/target/release])
        APR_ADDTO(MOD_LDFLAGS, [$ap_platform_runtime_link_flag$ap_wasmruntime_base/target/release])
      fi
    fi

    AC_MSG_CHECKING([for libwasm_runtime is available])
    AC_LANG([C])
    AC_TRY_COMPILE(
      [#include "wasm_runtime.h"],
      [wasm_runtime_init_module();],
      [AC_MSG_RESULT(OK)
       ac_cv_wasmruntime=yes],
      [AC_MSG_RESULT(FAILED)
       ac_cv_wasmruntime=no]
    )

    mod_wasm_version_major=`grep MOD_WASM_VERSION_MAJOR modules/wasm/mod_wasm.h | cut -d' ' -f3`
    mod_wasm_version_minor=`grep MOD_WASM_VERSION_MINOR modules/wasm/mod_wasm.h | cut -d' ' -f3`
    mod_wasm_version_patch=`grep MOD_WASM_VERSION_PATCH modules/wasm/mod_wasm.h | cut -d' ' -f3`
    mod_wasm_version="$mod_wasm_version_major"."$mod_wasm_version_minor"."$mod_wasm_version_patch"
    AC_MSG_CHECKING([for mod_wasm $mod_wasm_version compatibility])
    AC_LANG([C])
    AC_RUN_IFELSE(
      [AC_LANG_PROGRAM(
        [#include <stdio.h>
         #include "wasm_runtime.h"],
        [ printf("\n");
          printf("\tmod_wasm version is $mod_wasm_version\n");
          printf("\tlibwasm_runtime version is %s\n", WASM_RUNTIME_VERSION);
         if ( $mod_wasm_version_major == WASM_RUNTIME_VERSION_MAJOR
           && $mod_wasm_version_minor <= WASM_RUNTIME_VERSION_MINOR )
          exit(0);
         else
         {
          printf("\tIncompatible version numbers!\n");
          exit(1);
         }
        ]
      )],
      [AC_MSG_RESULT(OK)
       ac_cv_wasmruntime=yes],
      [AC_MSG_RESULT(FAILED)
       ac_cv_wasmruntime=no]
    )

    dnl restore
    CPPFLAGS="$saved_CPPFLAGS"
    LIBS="$saved_LIBS"
    LDFLAGS="$saved_LDFLAGS"
  ])
  if test "x$ac_cv_wasmruntime" = "xyes"; then
    AC_DEFINE(HAVE_WASMRUNTIME, 1, [Define if Wasm Runtime is available])
  fi
])


APACHE_MODULE(wasm, [WebAssembly handler module.
This module requires a libwasm_runtime installation.
See --with-wasmruntime on how to manage non-standard locations. This module
is usually linked shared and requires loading. ], $wasm_objs, , most, [
    APACHE_CHECK_WASMRUNTIME
    if test "$ac_cv_wasmruntime" = "yes" ; then
        if test "x$enable_wasm" = "xshared"; then
           case `uname` in
             "Darwin")
                MOD_WASM_LINK_LIBS="-lwasm_runtime -framework Foundation"
                ;;
             *)  
                MOD_WASM_LINK_LIBS="-lwasm_runtime"
                ;;
           esac

           APR_ADDTO(MOD_LDFLAGS, [$MOD_WASM_LINK_LIBS])
        fi
    else
        enable_wasm=no
    fi
])

APACHE_MODPATH_FINISH
