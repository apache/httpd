dnl ## XXX - Need a more thorough check of the proper flags to use

if test "$MPM_NAME" = "mpmt_beos" ; then
    apache_apr_flags="--enable-threads"

    APACHE_FAST_OUTPUT(server/mpm/$MPM_NAME/Makefile)
fi
