dnl modules enabled in this directory by default

dnl APACHE_MODULE(name, helptext[, objects[, structname[, default[, config]]]])

APACHE_MODPATH_INIT(metadata)

APACHE_MODULE(env, clearing/setting of ENV vars, , , yes)
APACHE_MODULE(mime_magic, automagically determining MIME type, , , no)
APACHE_MODULE(cern_meta, CERN-type meta files, , , no)
APACHE_MODULE(expires, Expires header control, , , no)
APACHE_MODULE(headers, HTTP header control, , , no)

APACHE_MODULE(usertrack, user-session tracking, , , no, [
  AC_CHECK_HEADERS(sys/times.h)
  AC_CHECK_FUNCS(times)
])

APACHE_MODULE(unique_id, per-request unique ids, , , no)
APACHE_MODULE(setenvif, basing ENV vars on headers, , , yes)

LTFLAGS="$LTFLAGS -export-dynamic"

APACHE_MODPATH_FINISH
