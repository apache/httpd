if test "$MPM_NAME" = "prefork" ; then
    APACHE_FAST_OUTPUT(server/mpm/$MPM_NAME/Makefile)
fi
