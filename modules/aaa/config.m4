
dnl ## mod_usertrack.c
AC_CHECK_HEADERS(sys/times.h)
AC_CHECK_FUNCS(times)

APACHE_MODULE(standard)
