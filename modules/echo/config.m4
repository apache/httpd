dnl modules enabled in this directory by default

dnl AC_DEFUN(modulename, modulestructname, defaultonoroff, configmacros)
dnl XXX - Need to allow --enable-module to fail if optional config fails

APACHE_MODPATH_INIT(echo)

APACHE_MODULE(echo, ECHO server, , , no)

LTFLAGS="$LTFLAGS -export-dynamic"

APACHE_MODPATH_FINISH
    
APACHE_SUBST(STANDARD_LIBS)
