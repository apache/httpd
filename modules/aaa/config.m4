dnl modules enabled in this directory by default

dnl AC_DEFUN(modulename, modulestructname, defaultonoroff, configmacros)
dnl XXX - Need to allow --enable-module to fail if optional config fails

AC_DEFUN(APACHE_CHECK_STANDARD_MODULE, [
  APACHE_MODULE([$1],[$2],,[$3],[$4],[$5])
])

APACHE_MODPATH_INIT(aaa)

APACHE_CHECK_STANDARD_MODULE(access, host-based access control, , yes)
APACHE_CHECK_STANDARD_MODULE(auth, user-based access control, , yes)
APACHE_CHECK_STANDARD_MODULE(auth_anon, anonymous user access, , no)
APACHE_CHECK_STANDARD_MODULE(auth_dbm, DBM-based access databases, , no)

APACHE_CHECK_STANDARD_MODULE(auth_db, DB-based access databases, , no, [
  AC_CHECK_HEADERS(db.h)
  AC_CHECK_LIB(db,main)
]) 
APACHE_CHECK_STANDARD_MODULE(auth_digest, digests, , no)

LTFLAGS="$LTFLAGS -export-dynamic"

APACHE_MODPATH_FINISH
    
APACHE_SUBST(STANDARD_LIBS)
