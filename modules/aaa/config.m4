dnl modules enabled in this directory by default

dnl AC_DEFUN(modulename, modulestructname, defaultonoroff, configmacros)
dnl XXX - Need to allow --enable-module to fail if optional config fails

AC_DEFUN(APACHE_CHECK_STANDARD_MODULE, [
  APACHE_MODULE($1,$2,,$3,$4,$5)
])

APACHE_MODPATH_INIT(standard)

dnl APACHE_MODULE(vhost_alias,blabla)
	
APACHE_CHECK_STANDARD_MODULE(vhost_alias, mass hosting module, , no)
APACHE_CHECK_STANDARD_MODULE(env, clearing/setting of ENV vars, , yes)
APACHE_CHECK_STANDARD_MODULE(log_config, logging configuration, config_log, yes)
APACHE_CHECK_STANDARD_MODULE(mime_magic, automagically determining MIME type, , no)
APACHE_CHECK_STANDARD_MODULE(mime, mapping of file-extension to MIME, , yes)
APACHE_CHECK_STANDARD_MODULE(negotiation, content negoatiation, , yes)
APACHE_CHECK_STANDARD_MODULE(status, process/thread monitoring, , no)
APACHE_CHECK_STANDARD_MODULE(include, Server Side Includes, includes, yes)
APACHE_CHECK_STANDARD_MODULE(autoindex, directory listing, , yes)
APACHE_CHECK_STANDARD_MODULE(dir, directory request handling, , yes)
APACHE_CHECK_STANDARD_MODULE(cgi, CGI scripts, , yes)
APACHE_CHECK_STANDARD_MODULE(cgid, CGI scripts, , no)
APACHE_CHECK_STANDARD_MODULE(asis, as-is filetypes, , yes)
APACHE_CHECK_STANDARD_MODULE(imap, internal imagemaps, , yes)
APACHE_CHECK_STANDARD_MODULE(actions, Action triggering on requests, action, yes)
APACHE_CHECK_STANDARD_MODULE(speling, correct common URL misspellings, , no)
APACHE_CHECK_STANDARD_MODULE(userdir, mapping of user requests, , yes)
APACHE_CHECK_STANDARD_MODULE(alias, translation of requests, , yes)
APACHE_CHECK_STANDARD_MODULE(rewrite, regex URL translation, , no)
APACHE_CHECK_STANDARD_MODULE(access, host-based access control, , yes)
APACHE_CHECK_STANDARD_MODULE(auth, user-based access control, , yes)
APACHE_CHECK_STANDARD_MODULE(auth_anon, anonymous user access, , no)
APACHE_CHECK_STANDARD_MODULE(auth_dbm, DBM-based access databases, , no)

APACHE_CHECK_STANDARD_MODULE(auth_db, DB-based access databases, , no, [
  AC_CHECK_HEADERS(db.h)
  AC_CHECK_LIB(db,main)
]) 

APACHE_CHECK_STANDARD_MODULE(auth_digest, digests, , no)
APACHE_CHECK_STANDARD_MODULE(cern_meta, CERN-type meta files, , no)
APACHE_CHECK_STANDARD_MODULE(expires, Expires header control, , no)
APACHE_CHECK_STANDARD_MODULE(headers, HTTP header control, , no)

APACHE_CHECK_STANDARD_MODULE(usertrack, user-session tracking, , no, [
  AC_CHECK_HEADERS(sys/times.h)
  AC_CHECK_FUNCS(times)
])

APACHE_CHECK_STANDARD_MODULE(unique_id, per-request unique ids, , no)
APACHE_CHECK_STANDARD_MODULE(setenvif, basing ENV vars on headers, , yes)
APACHE_CHECK_STANDARD_MODULE(echo, ECHO server, , yes)

LTFLAGS="$LTFLAGS -export-dynamic"

PLAT=`$ac_config_guess`
PLAT=`$ac_config_sub $PLAT`
case "$PLAT" in
    *-ibm-os390)
        ;;
    *-freebsd*)
        ;;
    *-os2_emx)
        ;;
    *-beos*)
        ;;
    *)
        LIBS="$LIBS -ldl"
        ;;
esac

if test "$sharedobjs" = "yes"; then
    APACHE_CHECK_STANDARD_MODULE(so, DSO capability, , yes)
else
    APACHE_CHECK_STANDARD_MODULE(so, DSO capability, , no)
fi
AC_CACHE_SAVE

APACHE_MODPATH_FINISH
    
APACHE_SUBST(STANDARD_LIBS)
