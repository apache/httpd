
APACHE_MODPATH_INIT(experimental)

if test "$ac_cv_ebcdic" = "yes"; then
# mod_charset_lite can be very useful on an ebcdic system, 
#   so include it by default
    APACHE_MODULE(charset_lite, character set translation, , , yes)
else
    APACHE_MODULE(charset_lite, character set translation, , , no)
fi

dnl #  list of object files for mod_cache
cache_objs="dnl
mod_cache.lo dnl
cache_storage.lo dnl
cache_util.lo dnl
" 
dnl #  list of object files for mod_mem_cache
mem_cache_objs="dnl
mod_mem_cache.lo dnl
cache_cache.lo dnl
cache_pqueue.lo dnl
cache_hash.lo dnl
" 
APACHE_MODULE(cache, dynamic file caching, $cache_objs, , no)
APACHE_MODULE(disk_cache, disk caching module, , , no)
APACHE_MODULE(mem_cache, memory caching module, $mem_cache_objs, , no)
APACHE_MODULE(example, example and demo module, , , no)
APACHE_MODULE(case_filter, example uppercase conversion filter, , , no)
APACHE_MODULE(case_filter_in, example uppercase conversion input filter, , , no)

ldap_objects="util_ldap.lo util_ldap_cache.lo util_ldap_cache_mgr.lo"
APACHE_MODULE(ldap, LDAP caching and connection pooling services, $ldap_objects, , no)

auth_ldap_objects="mod_auth_ldap.lo"
APACHE_MODULE(auth_ldap, LDAP based authentication, $auth_ldap_objects, , no)

APACHE_MODPATH_FINISH
