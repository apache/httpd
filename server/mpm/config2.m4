AC_MSG_CHECKING(which MPM to use by default)
AC_ARG_WITH(mpm,
APACHE_HELP_STRING(--with-mpm=MPM,Choose the process model for Apache to use by default.
                          MPM={simple|event|worker|prefork|winnt}
                          This will be statically linked as the only available MPM unless
                          --enable-mpms-shared is also specified.
),[
    default_mpm=$withval
    AC_MSG_RESULT($withval);
],[
    dnl Order of preference for default MPM: 
    dnl   The Windows and OS/2 MPMs are used on those platforms.
    dnl   Everywhere else: event, worker, prefork
    if ap_mpm_is_supported "winnt"; then
        default_mpm=winnt
        AC_MSG_RESULT(winnt)
    elif ap_mpm_is_supported "mpmt_os2"; then
        default_mpm=mpmt_os2
        AC_MSG_RESULT(mpmt_os2)
    elif ap_mpm_is_supported "event"; then
        default_mpm=event
        AC_MSG_RESULT(event)
    elif ap_mpm_is_supported "worker"; then
        default_mpm=worker
        AC_MSG_RESULT(worker - event is not supported)
    else
        default_mpm=prefork
        AC_MSG_RESULT(prefork - event and worker are not supported)
    fi
])

APACHE_MPM_ENABLED($default_mpm)

AC_ARG_ENABLE(mpms-shared,
APACHE_HELP_STRING(--enable-mpms-shared=MPM-LIST,Space-separated list of MPM modules to enable for dynamic loading.  MPM-LIST=list | "all"),[
    if test "$enableval" = "no"; then
        mpm_build=static
    else
        mpm_build=shared
dnl     Build just the default MPM if --enable-mpms-shared has no argument.
        if test "$enableval" = "yes"; then
            enableval=$default_mpm
        fi
        for i in $enableval; do
            if test "$i" = "all"; then
                for j in $ap_supported_shared_mpms; do
                    eval "enable_mpm_$j=shared"
                    APACHE_MPM_ENABLED($j)
                done
            else
                i=`echo $i | sed 's/-/_/g'`
                if ap_mpm_supports_shared $i; then
                    eval "enable_mpm_$i=shared"
                    APACHE_MPM_ENABLED($i)
                else
                    AC_MSG_ERROR([MPM $i does not support dynamic loading.])
                fi
            fi
        done
    fi
], [mpm_build=static])

for i in $ap_enabled_mpms; do
    if ap_mpm_is_supported $i; then
        :
    else
        AC_MSG_ERROR([MPM $i is not supported on this platform.])
    fi
done

if test $mpm_build = "shared"; then
    eval "tmp=\$enable_mpm_$default_mpm"
    if test "$tmp" != "shared"; then
        AC_MSG_ERROR([The default MPM ($default_mpm) must be included in --enable-mpms-shared.  Use --with-mpm to change the default MPM.])
    fi
fi

APACHE_FAST_OUTPUT(server/mpm/Makefile)

if test $mpm_build = "shared"; then
    MPM_LIB=""
else
    MPM_LIB=server/mpm/$default_mpm/lib${default_mpm}.la
    MODLIST="$MODLIST mpm_${default_mpm}"
fi

MPM_SUBDIRS=$ap_enabled_mpms
APACHE_SUBST(MPM_SUBDIRS)
APACHE_SUBST(MPM_LIB)
