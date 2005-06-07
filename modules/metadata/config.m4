dnl modules enabled in this directory by default

dnl APACHE_MODULE(name, helptext[, objects[, structname[, default[, config]]]])

APACHE_MODPATH_INIT(metadata)

APACHE_MODULE(env, clearing/setting of ENV vars, , , yes)
APACHE_MODULE(mime_magic, automagically determining MIME type)
APACHE_MODULE(cern_meta, CERN-type meta files)
APACHE_MODULE(expires, Expires header control, , , most)
APACHE_MODULE(headers, HTTP header control, , , most)
APACHE_MODULE(ident, RFC 1413 identity check, , , most)

APACHE_MODULE(usertrack, user-session tracking, , , , [
  AC_CHECK_HEADERS(sys/times.h)
  AC_CHECK_FUNCS(times)
])

APACHE_MODULE(unique_id, per-request unique ids)
APACHE_MODULE(setenvif, basing ENV vars on headers, , , yes)
APACHE_MODULE(version, determining httpd version in config files)

APACHE_MODPATH_FINISH
