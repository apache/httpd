dnl modules enabled in this directory by default

STANDARD_LIBS=""
AC_DEFUN(STANDARD_MODULE,[
  APACHE_MODULE($1)
  STANDARD_LIBS="$STANDARD_LIBS libapachemod_$1.la"
])

dnl AC_DEFUN(modulename, modulestructname, defaultonoroff)
dnl XXX - Need to add help text to --enable-module flags
dnl XXX - Need to add support for per-module config
AC_DEFUN(APACHE_CHECK_STANDARD_MODULE, [
    AC_MSG_CHECKING([whether to enable mod_$1])
    AC_ARG_ENABLE(patsubst([$1], _, -), [  --enable-]patsubst([$1], _, -), [],
        [enable_$1=]ifelse([$3], , no, [$3]))
    if test "$enable_[$1]" != "no" ; then
        MODLIST="$MODLIST ifelse([$2], , [$1], [$2])"
        STANDARD_MODULE([$1])
    fi
    AC_MSG_RESULT([$enable_$1])
])

APACHE_CHECK_STANDARD_MODULE(mmap_static, , no)
APACHE_CHECK_STANDARD_MODULE(vhost_alias, , no)
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

AC_CHECK_HEADERS(sys/times.h)
AC_CHECK_FUNCS(times)
APACHE_CHECK_STANDARD_MODULE(usertrack, , no)

APACHE_CHECK_STANDARD_MODULE(unique_id, , no)
APACHE_CHECK_STANDARD_MODULE(so, , no)
APACHE_CHECK_STANDARD_MODULE(setenvif, , yes)
APACHE_CHECK_STANDARD_MODULE(echo, , yes)

AC_SUBST(STANDARD_LIBS)
