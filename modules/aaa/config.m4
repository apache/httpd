dnl modules enabled in this directory by default

dnl APACHE_MODULE(name, helptext[, objects[, structname[, default[, config]]]])

APACHE_MODPATH_INIT(aaa)

APACHE_MODULE(access, host-based access control, , , yes)
APACHE_MODULE(auth, user-based access control, , , yes)
APACHE_MODULE(auth_anon, anonymous user access, , , most)
APACHE_MODULE(auth_dbm, DBM-based access databases, , , most)

APACHE_MODULE(auth_digest, RFC2617 Digest authentication, , , most, [
  ap_old_cppflags=$CPPFLAGS
  CPPFLAGS="$CPPFLAGS -I$APR_SOURCE_DIR/include -I$abs_builddir/srclib/apr/include"
  AC_TRY_COMPILE([#include <apr.h>], 
                 [#if !APR_HAS_RANDOM 
                  #error You need APR random support to use auth_digest. 
                  #endif],,
                 enable_auth_digest=no)
  CPPFLAGS=$ap_old_cppflags
])

APR_ADDTO(LT_LDFLAGS,-export-dynamic)

APACHE_MODPATH_FINISH
