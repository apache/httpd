dnl modules enabled in this directory by default

dnl APACHE_MODULE(name, helptext[, objects[, structname[, default[, config]]]])

APACHE_MODPATH_INIT(apreq)

APACHE_MODULE(apreq, Apache Request Filter, filter.lo handle.lo, , most)

APACHE_MODPATH_FINISH
