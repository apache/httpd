if test "$OS" = "unix" ; then
    AC_TYPE_RLIM_T

    AC_CHECK_HEADERS(sys/time.h sys/resource.h)

    AC_CHECK_FUNCS( \
    setsid \
    killpg \
    )
    
    dnl XXX - This doesn't deal with _sys_siglist. Maybe have to roll our own
    AC_DECL_SYS_SIGLIST
fi
