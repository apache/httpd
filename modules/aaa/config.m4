dnl modules enabled in this directory by default

dnl Authentication (authn), Access, and Authorization (authz)

dnl APACHE_MODULE(name, helptext[, objects[, structname[, default[, config]]]])

APACHE_MODPATH_INIT(aaa)

dnl Token modules: modules that parse or reference a token, that may
dnl contain or reference further data like usernames, or IP addresses.
dnl
APACHE_MODULE(autht_jwt, RFC7519 JSON Web Token based authentication control, , , most)

dnl General Authentication modules; module which implements the 
dnl non-autht module specific directives.
dnl
APACHE_MODULE(autht_core, core token authentication module, , , yes)

dnl Authentication modules; modules checking a username and password against a
dnl file, database, or other similar magic.
dnl
APACHE_MODULE(authn_file, file-based authentication control, , , yes)
APACHE_MODULE(authn_dbm, DBM-based authentication control, , , most)
APACHE_MODULE(authn_anon, anonymous user authentication control, , , most)
APACHE_MODULE(authn_dbd, SQL-based authentication control, , , most)
APACHE_MODULE(authn_socache, Cached authentication control, , , most)

dnl General Authentication modules; module which implements the 
dnl non-authn module specific directives.
dnl
APACHE_MODULE(authn_core, core authentication module, , , yes)

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
APACHE_MODULE(authz_dbd, SQL based authorization and Login/Session support, , , most)

dnl General Authorization modules; provider module which implements the 
dnl non-authz module specific directives.
dnl
APACHE_MODULE(authz_core, core authorization provider vector module, , , yes)

dnl LDAP authentication module. This module has both the authn and authz
dnl modules in one, so as to share the LDAP server config directives.
APACHE_MODULE(authnz_ldap, LDAP based authentication, , , most)

dnl FastCGI authorizer interface, supporting authn and authz.
APACHE_MODULE(authnz_fcgi,
              FastCGI authorizer-based authentication and authorization, , , no)

dnl - host access control compatibility modules. Implements Order, Allow,
dnl Deny, Satisfy for backward compatibility.  These directives have been
dnl deprecated in 2.4.
APACHE_MODULE(access_compat, mod_access compatibility, , , yes)

dnl these are the front-end authentication modules

APACHE_MODULE(auth_basic, basic authentication, , , yes)
APACHE_MODULE(auth_bearer, bearer authentication, , , yes)
APACHE_MODULE(auth_form, form authentication, , , most)
APACHE_MODULE(auth_digest, RFC2617 Digest authentication, , , most, [
  APR_CHECK_APR_DEFINE(APR_HAS_RANDOM)
  if test $ac_cv_define_APR_HAS_RANDOM = "no"; then
    echo "You need APR random support to use mod_auth_digest."
    echo "Look at APR configure options --with-egd and --with-devrandom."
    enable_auth_digest="no"
  fi
])

APACHE_MODULE(allowmethods, restrict allowed HTTP methods, , , most)
APACHE_MODULE(allowhandlers, restrict allowed handlers, , , most)

APR_ADDTO(INCLUDES, [-I\$(top_srcdir)/$modpath_current])

APACHE_MODPATH_FINISH
