dnl ## XXX - Need a more thorough check of the proper flags to use

if test "$MPM_NAME" = "dexter" ; then
    apache_apr_flags="--enable-threads"

    APACHE_FAST_OUTPUT(modules/mpm/$MPM_NAME/Makefile)
    APACHE_MPM_PTHREAD
fi
