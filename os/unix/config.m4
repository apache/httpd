if test "$OS" = "unix" ; then
    AC_TYPE_RLIM_T

    AC_CHECK_HEADERS(sys/time.h sys/resource.h)

    AC_CHECK_FUNCS(setsid killpg)
fi
