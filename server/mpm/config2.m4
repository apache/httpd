AC_MSG_CHECKING(which MPM to use)
AC_ARG_WITH(mpm,
APACHE_HELP_STRING(--with-mpm=MPM,Choose the process model for Apache to use.
                          MPM={simple|event|worker|prefork|winnt}
                          Specify "shared" instead of an MPM name to load MPMs dynamically.
),[
    APACHE_MPM=$withval
    AC_MSG_RESULT($withval);
],[
    dnl Order of preference for default MPM: 
    dnl   Windows: WinNT
    dnl   Everywhere else: event, worker, prefork
    if ap_mpm_is_supported "winnt"; then
        APACHE_MPM=winnt
        AC_MSG_RESULT(winnt)
    elif ap_mpm_is_supported "event"; then
        APACHE_MPM=event
        AC_MSG_RESULT(event)
    elif ap_mpm_is_supported "worker"; then
        APACHE_MPM=worker
        AC_MSG_RESULT(worker - event is not supported)
    else
        APACHE_MPM=prefork
        AC_MSG_RESULT(prefork - event and worker are not supported)
    fi
])

if test $APACHE_MPM = "shared"; then
    :
elif ap_mpm_is_supported $APACHE_MPM; then
    :
else
    AC_MSG_ERROR([The specified MPM, $APACHE_MPM, is not supported on this platform.])
fi

apache_cv_mpm=$APACHE_MPM
APACHE_MPM_ENABLED($APACHE_MPM)

APACHE_FAST_OUTPUT(server/mpm/Makefile)

if test "$apache_cv_mpm" = "shared"; then
    MPM_NAME=""
    MPM_SUBDIR_NAME=""
    MPM_LIB=""
else
    MPM_NAME=$apache_cv_mpm
    MPM_SUBDIR_NAME=$MPM_NAME
    MPM_LIB=server/mpm/$MPM_SUBDIR_NAME/lib${MPM_NAME}.la

    MODLIST="$MODLIST mpm_${MPM_NAME}"
fi

APACHE_SUBST(MPM_NAME)
APACHE_SUBST(MPM_SUBDIR_NAME)
APACHE_SUBST(MPM_LIB)
