dnl modules enabled in this directory by default

APACHE_MODPATH_INIT(http1)

http_objects="http1_core.lo http1_filters.lo http1_protocol.lo chunk_filter.lo"

dnl mod_http1 should only be built as a static module for now.
dnl this will hopefully be "fixed" at some point in the future by
dnl refactoring mod_http and moving some things to the core and
dnl vice versa so that the core does not depend upon mod_http1.
if test "$enable_http1" = "yes"; then
    enable_http1="static"
elif test "$enable_http1" = "shared"; then
    AC_MSG_ERROR([mod_http1 can not be built as a shared DSO])
fi

APACHE_MODULE(http1,[HTTP/1.x protocol handling.  The http module is a basic one that enables the server to function as an HTTP server. It is only useful to disable it if you want to use another protocol module instead. Don't disable this module unless you are really sure what you are doing. Note: This module will always be linked statically.], $http_objects, , static)

APACHE_MODPATH_FINISH
