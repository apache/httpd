AC_MSG_CHECKING(which MPM to use)
AC_ARG_WITH(mpm,
APACHE_HELP_STRING(--with-mpm=MPM,Choose the process model for Apache to use.
                          MPM={simple|event|worker|prefork|winnt}
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
APACHE_HELP_STRING(--enable-mpms-shared=MODULE-LIST,Space-separated list of shared MPM modules to enable | "all"),[
    mpm_build=shared
    for i in $enableval; do
        if test "$i" = "all"; then
            for j in $SUPPORTED_MPMS; do
                eval "enable_mpm_$j=shared"
                APACHE_MPM_ENABLED($j)
            done
        else
            i=`echo $i | sed 's/-/_/g'`
            eval "enable_mpm_$i=shared"
            APACHE_MPM_ENABLED($i)
        fi
    done
], [mpm_build=static])

for i in $ENABLED_MPMS; do
    if ap_mpm_is_supported $i; then
        :
    else
        AC_MSG_ERROR([MPM $i is not supported on this platform.])
    fi
done

APACHE_FAST_OUTPUT(server/mpm/Makefile)

if test $mpm_build = "shared"; then
    MPM_LIB=""
else
    MPM_LIB=server/mpm/$default_mpm/lib${default_mpm}.la
    MODLIST="$MODLIST mpm_${default_mpm}"
fi

MPM_SUBDIRS=$ENABLED_MPMS
APACHE_SUBST(MPM_SUBDIRS)
APACHE_SUBST(MPM_LIB)
