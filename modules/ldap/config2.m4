dnl modules enabled in this directory by default

APACHE_MODPATH_INIT(ldap)

ldap_objects="util_ldap.lo util_ldap_cache.lo util_ldap_cache_mgr.lo"
APACHE_MODULE(ldap, LDAP caching and connection pooling services, $ldap_objects, , no)

APACHE_MODPATH_FINISH
