dnl ## Check for libraries

AC_CHECK_LIB(nsl, gethostname, [
 AC_ADD_LIBRARY(nsl) ], [])

AC_CHECK_LIB(socket, socket, [
 AC_ADD_LIBRARY(socket) ], [])

AC_CHECK_LIB(nsl, gethostbyaddr, [
 AC_ADD_LIBRARY(nsl) ], [])

AC_CHECK_LIB(crypt, crypt, [
 AC_ADD_LIBRARY(crypt) 
 AC_DEFINE(HAVE_CRYPT)], [])

AC_CHECK_LIB(c, crypt, [
 AC_DEFINE(HAVE_CRYPT)], [])

dnl ## Check for header files

AC_HEADER_STDC
AC_CHECK_HEADERS(
bstring.h \
crypt.h \
unistd.h \
sys/resource.h \
sys/select.h \
sys/processor.h \
)

dnl ## Check for typedefs, structures, and compiler characteristics.

AC_CACHE_CHECK([for tm_gmtoff in struct tm], ac_cv_struct_tm_gmtoff,
[AC_TRY_COMPILE([#include <sys/types.h>
#include <$ac_cv_struct_tm>], [struct tm tm; tm.tm_gmtoff;],
  ac_cv_struct_tm_gmtoff=yes, ac_cv_struct_tm_gmtoff=no)])

if test "$ac_cv_struct_tm_gmtoff" = "yes"; then
    AC_DEFINE(HAVE_GMTOFF)
fi

dnl ## Check for library functions

AC_CHECK_FUNCS(
difftime \
syslog \
)
AC_FUNC_MMAP

dnl XXX - is autoconf's detection routine good enough?
if test "$ac_cv_func_mmap_fixed_mapped" = "yes"; then
    AC_DEFINE(USE_MMAP_FILES)
fi
