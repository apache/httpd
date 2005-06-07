dnl modules enabled in this directory by default

dnl APACHE_MODULE(name, helptext[, objects[, structname[, default[, config]]]])

APACHE_MODPATH_INIT(cache)

APACHE_MODULE(file_cache, File cache, , , no)

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

APACHE_MODPATH_FINISH
