
APACHE_MODPATH_INIT(experimental)

APACHE_MODULE(charset_lite, character set translation, , , no)
dnl #  list of object files for mod_cache
cache_objs="dnl
mod_cache.lo dnl
cache_storage.lo dnl
cache_util.lo dnl
" 
APACHE_MODULE(cache, dynamic file caching, $cache_objs, , no)
APACHE_MODULE(disk_cache, disk caching module, , , no)
APACHE_MODULE(example, example and demo module, , , no)
APACHE_MODULE(ext_filter, external filter module, , , no)
APACHE_MODULE(case_filter, example uppercase conversion filter, , , no)
APACHE_MODULE(case_filter_in, example uppercase conversion input filter, , , no)
APACHE_MODULE(optional_hook_export, example optional hook exporter, , , no)
APACHE_MODULE(optional_hook_import, example optional hook importer, , , no)
APACHE_MODULE(optional_fn_import, example optional function importer, , , no)
APACHE_MODULE(optional_fn_export, example optional function exporter, , , no)

APACHE_MODPATH_FINISH
