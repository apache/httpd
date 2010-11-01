dnl modules enabled in this directory by default

APACHE_MODPATH_INIT(http)

http_objects="http_core.lo http_protocol.lo http_request.lo http_filters.lo chunk_filter.lo byterange_filter.lo http_etag.lo"

dnl mod_http should only be built as a static module for now.
dnl this will hopefully be "fixed" at some point in the future by
dnl refactoring mod_http and moving some things to the core and
dnl vice versa so that the core does not depend upon mod_http.
if test "$enable_http" = "yes"; then
    enable_http="static"
elif test "$enable_http" = "shared"; then
    AC_MSG_ERROR([mod_http can not be built as a shared DSO])
fi

APACHE_MODULE(http,[HTTP protocol handling.  The http module is a basic one that enables the server to function as an HTTP server. It is only useful to disable it if you want to use another protocol module instead. Don't disable this module unless you are really sure what you are doing. Note: This module will always be linked statically.], $http_objects, , static)
APACHE_MODULE(mime, mapping of file-extension to MIME.  Disabling this module is normally not recommended., , , yes)

APACHE_MODPATH_FINISH
