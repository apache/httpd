dnl modules enabled in this directory by default

dnl AC_DEFUN(modulename, modulestructname, defaultonoroff, configmacros)
dnl XXX - Need to allow --enable-module to fail if optional config fails

AC_DEFUN(APACHE_CHECK_GENERATOR_MODULE, [
  APACHE_MODULE([$1],[$2],,[$3],[$4],[$5])
])

APACHE_MODPATH_INIT(generators)

APACHE_CHECK_GENERATOR_MODULE(status, process/thread monitoring, , no)
APACHE_CHECK_GENERATOR_MODULE(autoindex, directory listing, , yes)
APACHE_CHECK_GENERATOR_MODULE(asis, as-is filetypes, , yes)
APACHE_CHECK_GENERATOR_MODULE(info, server information, , no)
APACHE_CHECK_GENERATOR_MODULE(suexec, set uid and gid for spawned processes, , no)

LTFLAGS="$LTFLAGS -export-dynamic"

if test "$apache_cv_mpm" = "mpmt_pthread" -o "$apache_cv_mpm" = "dexter"; then
# if we are using a threaded MPM, we will get better performance with
# mod_cgid, so make it the default.
    APACHE_CHECK_GENERATOR_MODULE(cgid, CGI scripts, , yes)
    APACHE_CHECK_GENERATOR_MODULE(cgi, CGI scripts, , no)
else
# if we are using a non-threaded MPM, it makes little sense to use
# mod_cgid, and it just opens up holes we don't need.  Make mod_cgi the         # default
    APACHE_CHECK_GENERATOR_MODULE(cgi, CGI scripts, , yes)
    APACHE_CHECK_GENERATOR_MODULE(cgid, CGI scripts, , no)
fi

APACHE_MODPATH_FINISH
    
APACHE_SUBST(STANDARD_LIBS)
