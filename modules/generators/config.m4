dnl modules enabled in this directory by default

dnl AC_DEFUN(modulename, modulestructname, defaultonoroff, configmacros)
dnl XXX - Need to allow --enable-module to fail if optional config fails

AC_DEFUN(APACHE_CHECK_STANDARD_MODULE, [
  APACHE_MODULE([$1],[$2],,[$3],[$4],[$5])
])

APACHE_MODPATH_INIT(generators)

APACHE_CHECK_STANDARD_MODULE(status, process/thread monitoring, , no)
APACHE_CHECK_STANDARD_MODULE(autoindex, directory listing, , yes)
APACHE_CHECK_STANDARD_MODULE(asis, as-is filetypes, , yes)
APACHE_CHECK_STANDARD_MODULE(info, server information, , no)
APACHE_CHECK_STANDARD_MODULE(suexec, set uid and gid for spawned processes, , no)

LTFLAGS="$LTFLAGS -export-dynamic"

APACHE_MODPATH_FINISH
    
APACHE_SUBST(STANDARD_LIBS)
