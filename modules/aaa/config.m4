dnl modules enabled in this directory by default

dnl APACHE_MODULE(name, helptext[, objects[, structname[, default[, config]]]])

APACHE_MODPATH_INIT(aaa)

APACHE_MODULE(access, host-based access control, , , yes)
APACHE_MODULE(auth, user-based access control, , , yes)
APACHE_MODULE(auth_anon, anonymous user access, , , most)
APACHE_MODULE(auth_dbm, DBM-based access databases, , , most, [
  AC_SEARCH_LIBS(dbm_open,[c db1],,enable_auth_dbm=no)
  dnl Glibc 2.2's ndbm.h includes <db.h> in ndbm.h.  So, we need to find
  dnl where ndbm.h lives.  (2.2.4 looks like it includes <db1/db.h>.)
  AC_TRY_COMPILE([#include "ndbm.h"], [dbm_open("/dev/null", 0, 0)],
                 _good_db_path="yes", _good_db_path="no")
  if test "$_good_db_path" = "no"; then
    _old_cppflags=$CPPFLAGS
    CPPFLAGS="$CPPFLAGS -I/usr/include/db1"
    AC_TRY_COMPILE([#include "ndbm.h"], [dbm_open("/dev/null", 0, 0)],
                 _good_db_path="yes", _good_db_path="no")
    if test "$_good_db_path" = "no"; then
      CPPFLAGS=$_old_cppflags
      enable_auth_dbm=no
    fi
  fi
])

APACHE_MODULE(auth_db, DB-based access databases, , , , [
  AC_CHECK_HEADERS(db.h,,enable_auth_db=no)
  AC_SEARCH_LIBS(dbopen,[c db],,enable_auth_db=no)
]) 

APACHE_MODULE(auth_digest, RFC2617 Digest authentication, , , most, [
  _old_cppflags=$CPPFLAGS
  CPPFLAGS="$CPPFLAGS -I$APR_SOURCE_DIR/include"
  AC_TRY_COMPILE([#include <apr.h>], 
                 [#if !APR_HAS_RANDOM 
                  #error You need APR random support to use auth_digest. 
                  #endif],,
                 enable_auth_digest=no)
  CPPFLAGS=$_old_cppflags
])

APACHE_MODULE(auth_ldap, LDAP based authentication, , , no)

APR_ADDTO(LT_LDFLAGS,-export-dynamic)

APACHE_MODPATH_FINISH
