if test "$MPM_NAME" = "prefork" ; then
dnl Turn off all threading functions in APR
    apache_apr_flags="--disable-threads"

    APACHE_FAST_OUTPUT(server/mpm/$MPM_NAME/Makefile)

fi
