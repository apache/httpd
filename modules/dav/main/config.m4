dnl modules enabled in this directory by default

APACHE_MODPATH_INIT(dav/main)

APACHE_MODULE(dav, WebDAV protocol handling, , , yes)

APACHE_MODPATH_FINISH
