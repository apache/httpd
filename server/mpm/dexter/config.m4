dnl ## XXX - Need a more thorough check of the proper flags to use

if test "$MPM_NAME" = "dexter" ; then
    ac_cv_enable_threads="yes"
    AC_CACHE_SAVE

    APACHE_FAST_OUTPUT(modules/mpm/$MPM_NAME/Makefile)
    APACHE_MPM_PTHREAD
    APACHE_MPM_CHECK_SHMEM
fi
