if test "$OS" = "unix" ; then
    AC_CHECK_TYPE(rlim_t, [],
       AC_DEFINE_UNQUOTED(rlim_t, int,
          [Define to 'int' if <sys/resource.h> doesn't define it for us]),
          [#include <sys/types.h>
#include <sys/time.h>
#include <sys/resource.h>])

    AC_CHECK_HEADERS(sys/time.h sys/resource.h sys/sem.h sys/ipc.h)

    AC_CHECK_FUNCS(setsid killpg)
fi
