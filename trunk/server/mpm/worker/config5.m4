dnl ## XXX - Need a more thorough check of the proper flags to use

if test "$MPM_NAME" = "worker" ; then
    AC_CHECK_FUNCS(pthread_kill)
    APACHE_FAST_OUTPUT(server/mpm/$MPM_NAME/Makefile)
fi
