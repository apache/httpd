dnl ## Check for libraries

AC_CHECK_LIB(nsl, gethostname, APR_ADDTO(LIBS,-lnsl))
AC_CHECK_LIB(socket, socket, APR_ADDTO(LIBS,-lsocket))
AC_CHECK_LIB(nsl, gethostbyaddr, APR_ADDTO(LIBS,-lnsl))

dnl ## Check for header files

AC_CHECK_HEADERS(bstring.h unistd.h)

dnl ## Check for typedefs, structures, and compiler characteristics.

AC_CACHE_CHECK([for tm_gmtoff in struct tm], ac_cv_struct_tm_gmtoff,
[AC_TRY_COMPILE([#include <sys/types.h>
#include <$ac_cv_struct_tm>], [struct tm tm; tm.tm_gmtoff;],
  ac_cv_struct_tm_gmtoff=yes, ac_cv_struct_tm_gmtoff=no)])

if test "$ac_cv_struct_tm_gmtoff" = "yes"; then
    AC_DEFINE(HAVE_GMTOFF,,
        [Define if struct tm has a tm_gmtoff member])
fi

dnl ## Check for library functions

AC_CHECK_FUNCS(syslog)

dnl Obsolete scoreboard code uses this.
    AC_CHECK_HEADERS(sys/times.h)
    AC_CHECK_FUNCS(times)
