dnl ## XXX - Need a more thorough check of the proper flags to use

if test "$MPM_NAME" = "mpmt_pthread" ; then
    ac_cv_enable_threads="yes"
    AC_CACHE_SAVE

    APACHE_FAST_OUTPUT(modules/mpm/$MPM_NAME/Makefile)

    APACHE_MPM_PTHREAD
    APACHE_MPM_CHECK_SHMEM

dnl Obsolete scoreboard code uses this.
    AC_CHECK_HEADERS(sys/times.h)
    AC_CHECK_FUNCS(times)
fi
