if test "$OS" = "unix" ; then
    APACHE_TYPE_RLIM_T

    AC_CHECK_HEADERS(sys/time.h sys/resource.h sys/sem.h sys/ipc.h)

    AC_CHECK_FUNCS(setsid killpg)
fi
