dnl modules enabled in this directory by default

dnl AC_DEFUN(modulename, modulestructname, defaultonoroff, configmacros)
dnl XXX - Need to add help text to --enable-module flags
dnl XXX - Need to allow --enable-module to fail if optional config fails

AC_DEFUN(APACHE_CHECK_PROXY_MODULE, [
  APACHE_MODULE($1,,,$2,$3,$4)
])

APACHE_MODPATH_INIT(proxy)

APACHE_CHECK_PROXY_MODULE(proxy, , no)

APACHE_MODPATH_FINISH

APACHE_SUBST(STANDARD_LIBS)
