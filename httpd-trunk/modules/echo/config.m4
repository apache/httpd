dnl modules enabled in this directory by default

dnl APACHE_MODULE(name, helptext[, objects[, structname[, default[, config]]]])

APACHE_MODPATH_INIT(echo)

APACHE_MODULE(echo, ECHO server, , , )

APACHE_MODPATH_FINISH
