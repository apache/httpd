
APACHE_MODPATH_INIT(experimental)

APACHE_MODULE(mmap_static, memory mapped file caching, , , no)
APACHE_MODULE(charset_lite, character set translation, , , no)
APACHE_MODULE(cache, dynamic file caching, , , no)
APACHE_MODULE(disk_cache, disk caching module, , , no)

APACHE_MODPATH_FINISH
