dnl modules enabled in this directory by default

dnl AC_DEFUN(modulename, modulestructname, defaultonoroff, configmacros)
dnl XXX - Need to allow --enable-module to fail if optional config fails

AC_DEFUN(APACHE_CHECK_METADATA_MODULE, [
  APACHE_MODULE([$1],[$2],,[$3],[$4],[$5])
])

APACHE_MODPATH_INIT(metadata)

APACHE_CHECK_METADATA_MODULE(env, clearing/setting of ENV vars, , yes)
APACHE_CHECK_METADATA_MODULE(mime_magic, automagically determining MIME type, , no)
APACHE_CHECK_METADATA_MODULE(cern_meta, CERN-type meta files, , no)
APACHE_CHECK_METADATA_MODULE(expires, Expires header control, , no)
APACHE_CHECK_METADATA_MODULE(headers, HTTP header control, , no)

APACHE_CHECK_METADATA_MODULE(usertrack, user-session tracking, , no, [
  AC_CHECK_HEADERS(sys/times.h)
  AC_CHECK_FUNCS(times)
])

APACHE_CHECK_METADATA_MODULE(unique_id, per-request unique ids, , no)
APACHE_CHECK_METADATA_MODULE(setenvif, basing ENV vars on headers, , yes)

LTFLAGS="$LTFLAGS -export-dynamic"

APACHE_MODPATH_FINISH
    
APACHE_SUBST(STANDARD_LIBS)
