dnl modules enabled in this directory by default

dnl APACHE_MODULE(name, helptext[, objects[, structname[, default[, config]]]])

APACHE_MODPATH_INIT(echo)

APACHE_MODULE(echo, ECHO server, , , no)

APR_ADDTO(LT_LDFLAGS,-export-dynamic)

APACHE_MODPATH_FINISH
