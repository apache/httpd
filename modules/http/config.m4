dnl modules enabled in this directory by default

APACHE_MODPATH_INIT(http)

http_objects="http_core.lo http_protocol.lo http_request.lo"

APACHE_MODULE(http, HTTP protocol handling, $http_objects, , yes)
APACHE_MODULE(mime, mapping of file-extension to MIME, , , yes)


APACHE_MODPATH_FINISH
