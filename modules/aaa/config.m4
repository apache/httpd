dnl modules enabled in this directory by default

dnl AC_DEFUN(modulename, modulestructname, defaultonoroff, configmacros)
dnl XXX - Need to add help text to --enable-module flags
dnl XXX - Need to allow --enable-module to fail if optional config fails

AC_DEFUN(APACHE_CHECK_STANDARD_MODULE, [
  APACHE_MODULE($1,,,$2,$3,$4)
])

APACHE_MODPATH_INIT(standard)

APACHE_MODULE(vhost_alias,blabla)
	
dnl APACHE_CHECK_STANDARD_MODULE(vhost_alias, , no)
APACHE_CHECK_STANDARD_MODULE(env, , yes)
APACHE_CHECK_STANDARD_MODULE(log_config, config_log, yes)
APACHE_CHECK_STANDARD_MODULE(mime_magic, , no)
APACHE_CHECK_STANDARD_MODULE(mime, , yes)
APACHE_CHECK_STANDARD_MODULE(negotiation, , yes)
APACHE_CHECK_STANDARD_MODULE(status, , no)
APACHE_CHECK_STANDARD_MODULE(include, includes, yes)
APACHE_CHECK_STANDARD_MODULE(autoindex, , yes)
APACHE_CHECK_STANDARD_MODULE(dir, , yes)
APACHE_CHECK_STANDARD_MODULE(cgi, , yes)
APACHE_CHECK_STANDARD_MODULE(asis, , yes)
APACHE_CHECK_STANDARD_MODULE(imap, , yes)
APACHE_CHECK_STANDARD_MODULE(actions, action, yes)
APACHE_CHECK_STANDARD_MODULE(speling, , no)
APACHE_CHECK_STANDARD_MODULE(userdir, , yes)
APACHE_CHECK_STANDARD_MODULE(alias, , yes)
APACHE_CHECK_STANDARD_MODULE(rewrite, , no)
APACHE_CHECK_STANDARD_MODULE(access, , yes)
APACHE_CHECK_STANDARD_MODULE(auth, , yes)
APACHE_CHECK_STANDARD_MODULE(auth_anon, , no)
APACHE_CHECK_STANDARD_MODULE(auth_dbm, , no)
APACHE_CHECK_STANDARD_MODULE(auth_db, , no)
APACHE_CHECK_STANDARD_MODULE(auth_digest, , no)
APACHE_CHECK_STANDARD_MODULE(cern_meta, , no)
APACHE_CHECK_STANDARD_MODULE(expires, , no)
APACHE_CHECK_STANDARD_MODULE(headers, , no)

APACHE_CHECK_STANDARD_MODULE(usertrack, , no, [
  AC_CHECK_HEADERS(sys/times.h)
  AC_CHECK_FUNCS(times)
])

APACHE_CHECK_STANDARD_MODULE(unique_id, , no)
APACHE_CHECK_STANDARD_MODULE(so, , no)
APACHE_CHECK_STANDARD_MODULE(setenvif, , yes)
APACHE_CHECK_STANDARD_MODULE(echo, , yes)

APACHE_MODPATH_FINISH

if test "$sharedobjs" = "yes"; then
    LIBS="$LIBS -ldl"
    LTFLAGS="$LTFLAGS -export-dynamic"
fi
    
APACHE_SUBST(STANDARD_LIBS)
