dnl modules enabled in this directory by default

dnl APACHE_MODULE(name, helptext[, objects[, structname[, default[, config]]]])

APACHE_MODPATH_INIT(aaa)

APACHE_MODULE(access, host-based access control, , , yes)
APACHE_MODULE(auth, user-based access control, , , yes)
APACHE_MODULE(auth_anon, anonymous user access, , , most)
APACHE_MODULE(auth_dbm, DBM-based access databases, , , most)

APACHE_MODULE(auth_digest, RFC2617 Digest authentication, , , most, [
  APR_CHECK_APR_DEFINE(APR_HAS_RANDOM)
  if test $ac_cv_define_APR_HAS_RANDOM = "no"; then
    echo "You need APR random support to use mod_auth_digest."
    echo "Look at APR configure options --with-egd and --with-devrandom."
    enable_auth_digest="no"
  fi
])

APR_ADDTO(LT_LDFLAGS,-export-dynamic)

APACHE_MODPATH_FINISH
