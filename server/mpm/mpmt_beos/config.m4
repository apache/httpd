dnl ## XXX - Need a more thorough check of the proper flags to use

if test "$MPM_NAME" = "mpmt_beos" ; then
    ac_cv_enable_threads="yes"
    AC_CACHE_SAVE

    APACHE_FAST_OUTPUT(modules/mpm/$MPM_NAME/Makefile)
fi
