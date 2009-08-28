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
APACHE_MODULE(authn_dbd, SQL-based authentication control, , , most)

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
APACHE_MODULE(authnz_ldap, LDAP based authentication, , , no, [
  if test -z "$apu_config" ; then
      MOD_AUTHNZ_LDAP_LDADD="`$apr_config --ldap-libs`"
  else
      MOD_AUTHNZ_LDAP_LDADD="`$apu_config --ldap-libs`"
  fi
  AC_SUBST(MOD_AUTHNZ_LDAP_LDADD)
])

dnl - host access control compatibility modules. Implements Order, Allow,
dnl Deny, Satisfy for backward compatibility.  These directives have been
dnl deprecated in 2.4.
APACHE_MODULE(access_compat, mod_access compatibility, , , yes)

dnl these are the front-end authentication modules

APACHE_MODULE(auth_basic, basic authentication, , , yes)
APACHE_MODULE(auth_form, form authentication, , , yes)
APACHE_MODULE(auth_digest, RFC2617 Digest authentication, , , most, [
  APR_CHECK_APR_DEFINE(APR_HAS_RANDOM)
  if test $ac_cv_define_APR_HAS_RANDOM = "no"; then
    echo "You need APR random support to use mod_auth_digest."
    echo "Look at APR configure options --with-egd and --with-devrandom."
    enable_auth_digest="no"
  fi
])

APR_ADDTO(INCLUDES, [-I\$(top_srcdir)/$modpath_current])

APACHE_MODPATH_FINISH
