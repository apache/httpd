dnl modules enabled in this directory by default

dnl APACHE_MODULE(name, helptext[, objects[, structname[, default[, config]]]])

APACHE_MODPATH_INIT(aaa)

APACHE_MODULE(access, host-based access control, , , yes)
APACHE_MODULE(auth, user-based access control, , , yes)
APACHE_MODULE(auth_anon, anonymous user access, , , most)
APACHE_MODULE(auth_dbm, DBM-based access databases, , , most)

APACHE_MODULE(auth_db, DB-based access databases, , , , [
  AC_CHECK_HEADERS(db.h,,enable_auth_db=no)
  AC_CHECK_LIB(db,main,,enable_auth_db=no)
]) 

APACHE_MODULE(auth_digest, RFC2617 Digest authentication, , , most, [
  AC_TRY_COMPILE([#include <apr.h>], 
                 [#if !APR_HAS_RANDOM #error You need APR random support to use auth_digest. #endif],,
                 enable_auth_digest=no)
])

APACHE_MODULE(auth_ldap, LDAP based authentication, , , no)

APR_ADDTO(LT_LDFLAGS,-export-dynamic)

APACHE_MODPATH_FINISH
