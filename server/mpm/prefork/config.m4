if test "$MPM_NAME" = "prefork" ; then
dnl Turn off all threading functions in APR
    ac_cv_enable_threads="no"
    AC_CACHE_SAVE

    APACHE_FAST_OUTPUT(modules/mpm/$MPM_NAME/Makefile)

    APACHE_MPM_CHECK_SHMEM

dnl Obsolete scoreboard code uses this.
    AC_CHECK_HEADERS(sys/times.h)
    AC_CHECK_FUNCS(times)
fi
