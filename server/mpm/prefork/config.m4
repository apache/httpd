if test "$MPM_NAME" = "prefork" ; then
    APACHE_OUTPUT(modules/mpm/$MPM_NAME/Makefile)

    APACHE_MPM_CHECK_SHMEM

dnl Obsolete scoreboard code uses this.
    AC_CHECK_HEADERS(sys/times.h)
    AC_CHECK_FUNCS(times)
fi
