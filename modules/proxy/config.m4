dnl modules enabled in this directory by default

dnl AC_DEFUN(modulename, modulestructname, defaultonoroff, configmacros)
dnl XXX - Need to add help text to --enable-module flags
dnl XXX - Need to allow --enable-module to fail if optional config fails

AC_DEFUN(APACHE_CHECK_PROXY_MODULE, [
  APACHE_MODULE($1,,,$2,$3,$4)
])

APACHE_MODPATH_INIT(proxy)

APACHE_CHECK_PROXY_MODULE(proxy, , yes)

dnl APACHE_CHECK_STANDARD_MODULE(auth_db, , no, [
dnl   AC_CHECK_HEADERS(db.h)
dnl   AC_CHECK_LIB(db,main)
dnl ]) 

dnl APACHE_CHECK_STANDARD_MODULE(usertrack, , no, [
dnl   AC_CHECK_HEADERS(sys/times.h)
dnl   AC_CHECK_FUNCS(times)
dnl ])

APACHE_MODPATH_FINISH

if test "$sharedobjs" = "yes"; then
    LIBS="$LIBS -ldl"
    LTFLAGS="$LTFLAGS -export-dynamic"
fi
    
APACHE_SUBST(STANDARD_LIBS)
