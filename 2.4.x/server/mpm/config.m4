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
dnl XXX This hack tests for the underlying functions used by APR when it supports
dnl XXX APR_POLLSET_THREADSAFE, and duplicates APR's Darwin version check.
dnl A run-time check for
dnl     apr_pollset_create(,,APR_POLLSET_THREADSAFE) == APR_SUCCESS
dnl would be great but an in-tree apr (srclib/apr) hasn't been built yet.

AC_CACHE_CHECK([whether APR supports thread-safe pollsets], [ac_cv_have_threadsafe_pollset], [
    case $host in
        *-apple-darwin[[1-9]].*)
            APR_SETIFNULL(ac_cv_func_kqueue, [no])
            ;;
    esac
    AC_CHECK_FUNCS(kqueue port_create epoll_create)
    if test "$ac_cv_func_kqueue$ac_cv_func_port_create$ac_cv_func_epoll_create" != "nonono"; then
        ac_cv_have_threadsafe_pollset=yes
    else
        ac_cv_have_threadsafe_pollset=no
    fi
])

dnl See if APR has skiplist
dnl The base httpd prereq is APR 1.4.x, so we don't have to consider
dnl earlier versions.
case $APR_VERSION in
    1.4*)
        apr_has_skiplist=no
        ;;
    *)
        apr_has_skiplist=yes
esac

dnl See if this is a forking platform w.r.t. MPMs
case $host in
    *mingw32* | *os2-emx*)
        forking_mpms_supported=no
        ;;
    *)
        forking_mpms_supported=yes
        ;;
esac

dnl APACHE_MPM_SUPPORTED(name, supports-shared, is_threaded)
AC_DEFUN([APACHE_MPM_SUPPORTED],[
    if test "$2" = "yes"; then
        eval "ap_supported_mpm_$1=shared"
        ap_supported_shared_mpms="$ap_supported_shared_mpms $1 "
    else
        eval "ap_supported_mpm_$1=static"
    fi
    if test "$3" = "yes"; then
        eval "ap_threaded_mpm_$1=yes"
    fi
])dnl

dnl APACHE_MPM_ENABLED(name)
AC_DEFUN([APACHE_MPM_ENABLED],[
    if ap_mpm_is_enabled $1; then
        :
    else
        eval "ap_enabled_mpm_$1=yes"
        ap_enabled_mpms="$ap_enabled_mpms $1 "
    fi
])dnl

ap_mpm_is_supported ()
{
    eval "tmp=\$ap_supported_mpm_$1"
    if test -z "$tmp"; then
        return 1
    else
        return 0
    fi
}

ap_mpm_supports_shared ()
{
    eval "tmp=\$ap_supported_mpm_$1"
    if test "$tmp" = "shared"; then
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

    for mpm in $ap_enabled_mpms; do
        eval "tmp=\$ap_threaded_mpm_$mpm"
        if test "$tmp" = "yes"; then
            return 0
        fi
    done
    return 1
}

ap_mpm_is_enabled ()
{
    eval "tmp=\$ap_enabled_mpm_$1"
    if test "$tmp" = "yes"; then
        return 0
    else
        return 1
    fi
}
