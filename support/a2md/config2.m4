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

dnl # This file is intentionally named config2.m4 so that build/config-stubs
dnl # picks it up AFTER modules/md/config2.m4.  By that point the macros
dnl # APACHE_CHECK_OPENSSL, APACHE_CHECK_CURL, and APACHE_CHECK_JANSSON have
dnl # already run and their cached results (ac_cv_openssl, ac_cv_curl,
dnl # ac_cv_jansson) plus the lib-flag variables (ap_curl_libs, ap_jansson_libs)
dnl # are valid.
dnl #
dnl # The --enable-a2md option itself and a2md_LTFLAGS are declared earlier in
dnl # support/config.m4 (config.m4 sorts before config2.m4).

A2MD_LIBS=""

if test "x$enable_a2md" != "xno"; then
  if test "x$ac_cv_openssl" = "xyes" \
       -a "x$ac_cv_curl" = "xyes" \
       -a "x$ac_cv_jansson" = "xyes"; then
    APR_ADDTO(A2MD_LIBS, [$ap_curl_libs])
    APR_ADDTO(A2MD_LIBS, [$ap_jansson_libs])
    APR_ADDTO(A2MD_LIBS, [-lssl -lcrypto])
    AC_MSG_NOTICE([a2md: enabled (curl + jansson + openssl found)])
  else
    if test "x$enable_a2md" = "xyes"; then
      AC_MSG_ERROR([--enable-a2md requested but required libraries (openssl/curl/jansson) are missing])
    else
      AC_MSG_NOTICE([a2md: skipped (missing openssl, curl, or jansson)])
      enable_a2md="no"
    fi
  fi
fi

APACHE_SUBST(A2MD_LIBS)
