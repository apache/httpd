if test "$MPM_NAME" = "spmt_os2" ; then
    AC_CACHE_SAVE
    APACHE_FAST_OUTPUT(modules/mpm/$MPM_NAME/Makefile)
    CFLAGS="$CFLAGS -Zmt"
    LDFLAGS="$LDFLAGS -Zmt"
fi
