dnl modules enabled in this directory by default

dnl Authentication (authn), Access, and Authorization (authz)

dnl APACHE_MODULE(name, helptext[, objects[, structname[, default[, config]]]])

APACHE_MODPATH_INIT(aaa)

dnl Authentication modules; modules checking a username and password against a
dnl file, database, or other similar magic.
dnl
APACHE_MODULE(authn_file, file-based authentication control, , , yes)
APACHE_MODULE(authn_dbm, DBM-based authentication control, , , most)
APACHE_MODULE(authn_anon, anonymous user authentication control, , , most)

dnl - and just in case all of the above punt; a default handler to
dnl keep the bad guys out.
APACHE_MODULE(authn_default, authentication backstopper, , , yes)

dnl Authorization modules: modules which verify a certain property such as
dnl membership of a group, value of the IP address against a list of pre
dnl configured directives (e.g. require, allow) or against an external file
dnl or database.
dnl
APACHE_MODULE(authz_host, host-based authorization control, , , yes)
APACHE_MODULE(authz_groupfile, 'require group' authorization control, , , yes)
APACHE_MODULE(authz_user, 'require user' authorization control, , , yes)
APACHE_MODULE(authz_dbm, DBM-based authorization control, , , most)
APACHE_MODULE(authz_owner, 'require file-owner' authorization control, , , most)

dnl - and just in case all of the above punt; a default handler to
dnl keep the bad guys out.
APACHE_MODULE(authz_default, authorization control backstopper, , , yes)

dnl these are the front-end authentication modules

APACHE_MODULE(auth_basic, basic authentication, , , yes)
APACHE_MODULE(auth_digest, RFC2617 Digest authentication, , , most, [
  APR_CHECK_APR_DEFINE(APR_HAS_RANDOM)
  if test $ac_cv_define_APR_HAS_RANDOM = "no"; then
    echo "You need APR random support to use mod_auth_digest."
    echo "Look at APR configure options --with-egd and --with-devrandom."
    enable_auth_digest="no"
  fi
])

APACHE_MODPATH_FINISH
