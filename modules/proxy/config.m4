dnl modules enabled in this directory by default

dnl APACHE_MODULE(name, helptext[, objects[, structname[, default[, config]]]])

dnl XXX - Need to add help text to --enable-module flags
dnl XXX - Need to allow --enable-module to fail if optional config fails

APACHE_MODPATH_INIT(proxy)

APACHE_MODULE(proxy, proxy handling, , , no)

APACHE_MODPATH_FINISH
