dnl modules enabled in this directory by default

dnl APACHE_MODULE(name, helptext[, objects[, structname[, default[, config]]]])

APACHE_MODPATH_INIT(cache)

APACHE_MODULE(file_cache, File cache, , , no)

APACHE_MODPATH_FINISH
