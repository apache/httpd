
dnl APACHE_MODULE(name, helptext[, objects[, structname[, default[, config]]]])

APACHE_MODPATH_INIT(ldap)

ldap_objects="util_ldap.lo util_ldap_cache.lo util_ldap_cache_mgr.lo"
APACHE_MODULE(ldap, LDAP caching and connection pooling services, $ldap_objects, , no, [
  MOD_LDAP_LDADD="`$apu_config --ldap-libs`" || MOD_LDAP_LDADD=""
  AC_SUBST(MOD_LDAP_LDADD)
])

APACHE_MODPATH_FINISH
