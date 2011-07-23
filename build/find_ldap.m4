dnl -------------------------------------------------------- -*- autoconf -*-
dnl Licensed to the Apache Software Foundation (ASF) under one or more
dnl contributor license agreements.  See the NOTICE file distributed with
dnl this work for additional information regarding copyright ownership.
dnl The ASF licenses this file to You under the Apache License, Version 2.0
dnl (the "License"); you may not use this file except in compliance with
dnl the License.  You may obtain a copy of the License at
dnl
dnl     http://www.apache.org/licenses/LICENSE-2.0
dnl
dnl Unless required by applicable law or agreed to in writing, software
dnl distributed under the License is distributed on an "AS IS" BASIS,
dnl WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
dnl See the License for the specific language governing permissions and
dnl limitations under the License.


dnl 
dnl Find a particular LDAP library
dnl
AC_DEFUN([AP_FIND_LDAPLIB], [
  if test ${ap_has_ldap} != "1"; then
    ldaplib=$1
    extralib=$2
    # Clear the cache entry for subsequent AP_FIND_LDAPLIB invocations.
    changequote(,)
    ldaplib_cache_id="`echo $ldaplib | sed -e 's/[^a-zA-Z0-9_]/_/g'`"
    changequote([,])
    unset ac_cv_lib_${ldaplib_cache_id}_ldap_init
    unset ac_cv_lib_${ldaplib_cache_id}___ldap_init
    AC_CHECK_LIB(${ldaplib}, ldap_init, 
      [
        LDADD_ldap="-l${ldaplib} ${extralib}"
        AC_CHECK_LIB(${ldaplib}, ldapssl_client_init, ap_has_ldapssl_client_init="1", , ${extralib})
        AC_CHECK_LIB(${ldaplib}, ldapssl_client_deinit, ap_has_ldapssl_client_deinit="1", , ${extralib})
        AC_CHECK_LIB(${ldaplib}, ldapssl_add_trusted_cert, ap_has_ldapssl_add_trusted_cert="1", , ${extralib})
        AC_CHECK_LIB(${ldaplib}, ldap_start_tls_s, ap_has_ldap_start_tls_s="1", , ${extralib})
        AC_CHECK_LIB(${ldaplib}, ldap_sslinit, ap_has_ldap_sslinit="1", , ${extralib})
        AC_CHECK_LIB(${ldaplib}, ldapssl_init, ap_has_ldapssl_init="1", , ${extralib})
        AC_CHECK_LIB(${ldaplib}, ldapssl_install_routines, ap_has_ldapssl_install_routines="1", , ${extralib})
        ap_has_ldap="1";
      ], , ${extralib})
  fi
])


dnl
dnl AP_FIND_LDAP: figure out where LDAP is located
dnl
AC_DEFUN([AP_FIND_LDAP],  [

echo $ac_n "${nl}checking for ldap support..."

ap_has_ldap="0";
ap_has_ldapssl_client_init="0"
ap_has_ldapssl_client_deinit="0"
ap_has_ldapssl_add_trusted_cert="0"
ap_has_ldap_start_tls_s="0"
ap_has_ldapssl_init="0"
ap_has_ldap_sslinit="0"
ap_has_ldapssl_install_routines="0"
ap_has_ldap_openldap="0"
ap_has_ldap_solaris="0"
ap_has_ldap_novell="0"
ap_has_ldap_microsoft="0"
ap_has_ldap_netscape="0"
ap_has_ldap_mozilla="0"
ap_has_ldap_tivoli="0"
ap_has_ldap_zos="0"
ap_has_ldap_other="0"
LDADD_ldap=""

AC_ARG_WITH(lber,[  --with-lber=library     lber library to use],
  [
    if test "$withval" = "yes"; then
      ap_liblber_name="lber"
    else
      ap_liblber_name="$withval"
    fi
  ],
  [
    ap_liblber_name="lber"
  ])

AC_ARG_WITH(ldap-include,[  --with-ldap-include=path  path to ldap include files with trailing slash])
AC_ARG_WITH(ldap-lib,[  --with-ldap-lib=path    path to ldap lib file])
AC_ARG_WITH(ldap,[  --with-ldap=library     ldap library to use],
  [
    if test "$with_ldap" != "no"; then
      save_cppflags="$CPPFLAGS"
      save_ldflags="$LDFLAGS"
      save_libs="$LIBS"
      if test -n "$with_ldap_include"; then
        CPPFLAGS="$CPPFLAGS -I$with_ldap_include"
        APR_ADDTO(INCLUDES, [-I$with_ldap_include])
      fi
      if test -n "$with_ldap_lib"; then
        APR_ADDTO(LDFLAGS, [-L$with_ldap_lib])
      fi

      LIBLDAP="$withval"
      if test "$LIBLDAP" = "yes"; then
        dnl The iPlanet C SDK 5.0 is as yet untested... 
        AP_FIND_LDAPLIB("ldap50", "-lnspr4 -lplc4 -lplds4 -liutil50 -llber50 -lldif50 -lnss3 -lprldap50 -lssl3 -lssldap50")
        AP_FIND_LDAPLIB("ldapssl41", "-lnspr3 -lplc3 -lplds3")
        AP_FIND_LDAPLIB("ldapssl40")
        AP_FIND_LDAPLIB("ldapssl30")
        AP_FIND_LDAPLIB("ldapssl20")
        AP_FIND_LDAPLIB("ldapsdk", "-lldapx -lldapssl -lldapgss -lgssapi_krb5")
        AP_FIND_LDAPLIB("ldapsdk", "-lldapx -lldapssl -lldapgss -lgss -lresolv -lsocket")
        AP_FIND_LDAPLIB("ldap", "-llber")
        AP_FIND_LDAPLIB("ldap", "-llber -lresolv")
        AP_FIND_LDAPLIB("ldap", "-llber -lresolv -lsocket -lnsl")
        AP_FIND_LDAPLIB("ldap", "-ldl -lpthread")
      else
        AP_FIND_LDAPLIB($LIBLDAP)
        AP_FIND_LDAPLIB($LIBLDAP, "-lresolv")
        AP_FIND_LDAPLIB($LIBLDAP, "-lresolv -lsocket -lnsl")
        AP_FIND_LDAPLIB($LIBLDAP, "-ldl -lpthread")
      fi

      test ${ap_has_ldap} != "1" && AC_MSG_ERROR(could not find an LDAP library)
      AC_CHECK_LIB($ap_liblber_name, ber_init,
        [LDADD_ldap="${LDADD_ldap} -l${ap_liblber_name}"])

      AC_CHECK_HEADERS(lber.h, lber_h=["#include <lber.h>"])

      # Solaris has a problem in <ldap.h> which prevents it from
      # being included by itself.  Check for <ldap.h> manually,
      # including lber.h first.
      AC_CACHE_CHECK([for ldap.h], [ap_cv_hdr_ldap_h],
      [AC_TRY_CPP(
      [#ifdef HAVE_LBER_H
      #include <lber.h>
      #endif
      #include <ldap.h>
      ], [ap_cv_hdr_ldap_h=yes], [ap_cv_hdr_ldap_h=no])])
      if test "$ap_cv_hdr_ldap_h" = "yes"; then
        ldap_h=["#include <ldap.h>"]
        AC_DEFINE([HAVE_LDAP_H], 1, [Defined if ldap.h is present])
      fi

      AC_CHECK_HEADERS(ldap_ssl.h, ldap_ssl_h=["#include <ldap_ssl.h>"])

      if test "$ap_cv_hdr_ldap_h" = "yes"; then
        AC_CACHE_CHECK([for LDAP toolkit],
                       [ap_cv_ldap_toolkit], [
          if test "x$ap_cv_ldap_toolkit" = "x"; then
            AC_EGREP_CPP([OpenLDAP], [$lber_h
                         $ldap_h 
                         LDAP_VENDOR_NAME], [ap_has_ldap_openldap="1"
                                             ap_cv_ldap_toolkit="OpenLDAP"])
          fi
          if test "x$ap_cv_ldap_toolkit" = "x"; then
            AC_EGREP_CPP([Sun Microsystems Inc.], [$lber_h
                         $ldap_h
                         LDAP_VENDOR_NAME], [ap_has_ldap_solaris="1"
                                             ap_cv_ldap_toolkit="Solaris"])
          fi
          if test "x$ap_cv_ldap_toolkit" = "x"; then
            AC_EGREP_CPP([Novell], [$lber_h
                         $ldap_h
                         LDAP_VENDOR_NAME], [ap_has_ldap_novell="1"
                                             ap_cv_ldap_toolkit="Novell"])
          fi
          if test "x$ap_cv_ldap_toolkit" = "x"; then
            AC_EGREP_CPP([Microsoft Corporation.], [$lber_h
                         $ldap_h
                         LDAP_VENDOR_NAME], [ap_has_ldap_microsoft="1"
                                             ap_cv_ldap_toolkit="Microsoft"])
          fi
          if test "x$ap_cv_ldap_toolkit" = "x"; then
            AC_EGREP_CPP([Netscape Communications Corp.], [$lber_h
                         $ldap_h
                         LDAP_VENDOR_NAME], [ap_has_ldap_netscape="1"
                                             ap_cv_ldap_toolkit="Netscape"])
          fi
          if test "x$ap_cv_ldap_toolkit" = "x"; then
            AC_EGREP_CPP([mozilla.org], [$lber_h
                         $ldap_h
                         LDAP_VENDOR_NAME], [ap_has_ldap_mozilla="1"
                                             ap_cv_ldap_toolkit="Mozilla"])
          fi
          if test "x$ap_cv_ldap_toolkit" = "x"; then
            AC_EGREP_CPP([International Business Machines], [$lber_h
                         $ldap_h
                         LDAP_VENDOR_NAME], [ap_has_ldap_tivoli="1"
                                             ap_cv_ldap_toolkit="Tivoli"])
          fi
          if test "x$ap_cv_ldap_toolkit" = "x"; then
            case "$host" in
            *-ibm-os390)
              AC_EGREP_CPP([IBM], [$lber_h
                                   $ldap_h], [ap_has_ldap_zos="1"
                                              ap_cv_ldap_toolkit="z/OS"])
              ;;
            esac
          fi
          if test "x$ap_cv_ldap_toolkit" = "x"; then
            ap_has_ldap_other="1"
            ap_cv_ldap_toolkit="unknown"
          fi
        ])
      fi

      CPPFLAGS=$save_cppflags
      LDFLAGS=$save_ldflags
      LIBS=$save_libs
    fi
  ])

if test "$ap_has_ldap_openldap" = "1"; then
    save_cppflags="$CPPFLAGS"
    save_ldflags="$LDFLAGS"
    save_libs="$LIBS"

    CPPFLAGS="$CPPFLAGS $INCLUDES"
    AC_CACHE_CHECK([style of ldap_set_rebind_proc routine], ac_cv_ldap_set_rebind_proc_style,
    APR_TRY_COMPILE_NO_WARNING([
    #ifdef HAVE_LBER_H
    #include <lber.h>
    #endif
    #ifdef HAVE_LDAP_H
    #include <ldap.h>
    #endif
    ], [
    int tmp = ldap_set_rebind_proc((LDAP *)0, (LDAP_REBIND_PROC *)0, (void *)0);
    /* use tmp to suppress the warning */
    tmp=0;
    ], ac_cv_ldap_set_rebind_proc_style=three, ac_cv_ldap_set_rebind_proc_style=two))

    if test "$ac_cv_ldap_set_rebind_proc_style" = "three"; then
        AC_DEFINE(LDAP_SET_REBIND_PROC_THREE, 1, [Define if ldap_set_rebind_proc takes three arguments])
    fi

    CPPFLAGS="$save_cppflags"
    LDFLAGS="$save_ldflags"
    LIBS="$save_libs"
fi

AC_SUBST(ldap_h)
AC_SUBST(lber_h)
AC_SUBST(ldap_ssl_h)
AC_SUBST(ap_has_ldapssl_client_init)
AC_SUBST(ap_has_ldapssl_client_deinit)
AC_SUBST(ap_has_ldapssl_add_trusted_cert)
AC_SUBST(ap_has_ldap_start_tls_s)
AC_SUBST(ap_has_ldapssl_init)
AC_SUBST(ap_has_ldap_sslinit)
AC_SUBST(ap_has_ldapssl_install_routines)
AC_SUBST(ap_has_ldap)
AC_SUBST(ap_has_ldap_openldap)
AC_SUBST(ap_has_ldap_solaris)
AC_SUBST(ap_has_ldap_novell)
AC_SUBST(ap_has_ldap_microsoft)
AC_SUBST(ap_has_ldap_netscape)
AC_SUBST(ap_has_ldap_mozilla)
AC_SUBST(ap_has_ldap_tivoli)
AC_SUBST(ap_has_ldap_zos)
AC_SUBST(ap_has_ldap_other)
AC_SUBST(LDADD_ldap)
AC_CONFIG_FILES(include/ap_ldap.h)
])
