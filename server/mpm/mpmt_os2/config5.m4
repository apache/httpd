if test "$MPM_NAME" = "mpmt_os2" ; then
    AC_CACHE_SAVE
    APACHE_FAST_OUTPUT(server/mpm/$MPM_NAME/Makefile)
    APR_ADDTO(CFLAGS,-Zmt)
fi
