dnl modules enabled in this directory by default

dnl APACHE_MODULE(name, helptext[, objects[, structname[, default[, config]]]])

APACHE_MODPATH_INIT(filters)

APACHE_MODULE(include, Server Side Includes, , , yes)

APR_ADDTO(LTFLAGS,-export-dynamic)

APACHE_MODPATH_FINISH
