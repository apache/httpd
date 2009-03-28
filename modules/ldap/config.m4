
dnl APACHE_MODULE(name, helptext[, objects[, structname[, default[, config]]]])

APACHE_MODPATH_INIT(ldap)

ldap_objects="util_ldap.lo util_ldap_cache.lo util_ldap_cache_mgr.lo"
APACHE_MODULE(ldap, LDAP caching and connection pooling services, $ldap_objects, , no, [
  if test -z "$apu_config" ; then
      MOD_LDAP_LDADD="`$apr_config --ldap-libs`"
  else
      MOD_LDAP_LDADD="`$apu_config --ldap-libs`"
  fi
  AC_SUBST(MOD_LDAP_LDADD)
])

APACHE_MODPATH_FINISH
