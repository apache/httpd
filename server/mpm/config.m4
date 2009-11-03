dnl common platform checks needed by MPMs, methods for MPMs to state
dnl their support for the platform, functions to query MPM properties

APR_CHECK_APR_DEFINE(APR_HAS_THREADS)

have_threaded_sig_graceful=yes
case $host in
    *-linux-*)
        case `uname -r` in
          2.0* )
            dnl Threaded MPM's are not supported on Linux 2.0
            dnl as on 2.0 the linuxthreads library uses SIGUSR1
            dnl and SIGUSR2 internally
            have_threaded_sig_graceful=no
          ;;
        esac
    ;;
esac

dnl See if APR supports APR_POLLSET_THREADSAFE.
dnl XXX This hack tests for the underlying functions used by APR when it
dnl XXX supports APR_POLLSET_THREADSAFE.
dnl FIXME with a run-time check for
dnl     apr_pollset_create(,,APR_POLLSET_THREADSAFE) == APR_SUCCESS
AC_CHECK_FUNCS(kqueue port_create epoll_create)
if test "$ac_cv_func_kqueue$ac_cv_func_port_create$ac_cv_func_epoll_create" != "nonono"; then
    have_threadsafe_pollset=yes
else
    have_threadsafe_pollset=no
fi

dnl See if this is a forking platform w.r.t. MPMs
case $host in
    *mingw32*)
        forking_mpms_supported=no
        ;;
    *)
        forking_mpms_supported=yes
        ;;
esac

dnl APACHE_MPM_SUPPORTED(name, supports-shared, is_threaded)
AC_DEFUN(APACHE_MPM_SUPPORTED,[
    SUPPORTED_MPMS="$SUPPORTED_MPMS $1 "
    if test "$3" = "yes"; then
        THREADED_MPMS="$THREADED_MPMS $1 "
    fi
])dnl

dnl APACHE_MPM_ENABLED(name)
AC_DEFUN(APACHE_MPM_ENABLED,[
    ENABLED_MPMS="$ENABLED_MPMS $1 "
])dnl

ap_mpm_is_supported ()
{
    if echo "$SUPPORTED_MPMS" | grep " $1 " >/dev/null; then
        return 0
    else
        return 1
    fi
}

ap_mpm_is_threaded ()
{
    if test "$mpm_build" = "shared" -a ac_cv_define_APR_HAS_THREADS = "yes"; then
        return 0
    fi

    for mpm in $ENABLED_MPMS; do
        if echo "$THREADED_MPMS" | grep " $mpm " >/dev/null; then
            return 0
        fi
    done
    return 1
}

ap_mpm_is_enabled ()
{
    if echo "$ENABLED_MPMS" | grep " $1 " >/dev/null; then
        return 0
    else
        return 1
    fi
}
