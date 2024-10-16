
dnl APACHE_MODULE(name, helptext[, objects[, structname[, default[, config]]]])

APACHE_MODPATH_INIT(ldap)

ldap_objects="util_ldap.lo util_ldap_cache.lo util_ldap_cache_mgr.lo"
APACHE_MODULE(ldap, LDAP caching and connection pooling services, $ldap_objects, , most)

APR_ADDTO(INCLUDES, [-I\$(top_srcdir)/$modpath_current])

APACHE_MODPATH_FINISH
