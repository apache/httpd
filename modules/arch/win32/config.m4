dnl modules enabled in this directory by default

dnl APACHE_MODULE(name, helptext[, objects[, structname[, default[, config]]]])

APACHE_MODPATH_INIT(arch/win32)

APACHE_MODULE(isapi, isapi extension support, , , no)

APACHE_MODPATH_FINISH
