dnl modules enabled in this directory by default

dnl APACHE_MODULE(name, helptext[, objects[, structname[, default[, config]]]])

APACHE_MODPATH_INIT(arch/win32)

APACHE_MODULE(isapi, isapi extension support, , , no)

APR_ADDTO(LT_LDFLAGS,-export-dynamic)

APACHE_MODPATH_FINISH
