dnl modules enabled in this directory by default

dnl AC_DEFUN(modulename, modulestructname, defaultonoroff, configmacros)
dnl XXX - Need to allow --enable-module to fail if optional config fails

AC_DEFUN(APACHE_CHECK_MAPPERS_MODULE, [
  APACHE_MODULE([$1],[$2],,[$3],[$4],[$5])
])

APACHE_MODPATH_INIT(mappers)

APACHE_CHECK_MAPPERS_MODULE(vhost_alias, mass hosting module, , no)
APACHE_CHECK_MAPPERS_MODULE(negotiation, content negoatiation, , yes)
APACHE_CHECK_MAPPERS_MODULE(dir, directory request handling, , yes)
APACHE_CHECK_MAPPERS_MODULE(imap, internal imagemaps, , yes)
APACHE_CHECK_MAPPERS_MODULE(actions, Action triggering on requests, action, yes)
APACHE_CHECK_MAPPERS_MODULE(speling, correct common URL misspellings, , no)
APACHE_CHECK_MAPPERS_MODULE(userdir, mapping of user requests, , yes)
APACHE_CHECK_MAPPERS_MODULE(alias, translation of requests, , yes)

APACHE_CHECK_MAPPERS_MODULE(rewrite, regex URL translation, , no, [
  EXTRA_CFLAGS="$EXTRA_CFLAGS -DNO_DBM_REWRITEMAP"
])

APACHE_MODPATH_FINISH
    
APACHE_SUBST(STANDARD_LIBS)
