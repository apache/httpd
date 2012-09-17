dnl ## Check for libraries

dnl ## Check for header files

AC_CHECK_HEADERS(bstring.h unistd.h)

dnl ## Check for typedefs, structures, and compiler characteristics.

dnl ## Check for library functions

AC_CHECK_FUNCS(syslog)

dnl Obsolete scoreboard code uses this.
    AC_CHECK_HEADERS(sys/times.h)
    AC_CHECK_FUNCS(times)

dnl Add expr header files to INCLUDES
# util_expr needs header files in server source dir
APR_ADDTO(INCLUDES, [-I\$(top_srcdir)/server])
