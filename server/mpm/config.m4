AC_MSG_CHECKING(which MPM to use)
AC_ARG_WITH(mpm,
APACHE_HELP_STRING(--with-mpm=MPM,Choose the process model for Apache to use.
                          MPM={simple|event|worker|prefork|mpmt_os2|winnt}
                          Specify "shared" instead of an MPM name to load MPMs dynamically.
),[
  APACHE_MPM=$withval
],[
  if test "x$APACHE_MPM" = "x"; then
    APACHE_MPM=simple
  fi
])
AC_MSG_RESULT($APACHE_MPM)

apache_cv_mpm=$APACHE_MPM

dnl Note that a build with an explicitly loaded MPM must support threaded MPMs.
ap_mpm_is_threaded ()
{
    if test "$apache_cv_mpm" = "shared" -o "$apache_cv_mpm" = "worker" -o "$apache_cv_mpm" = "event" -o "$apache_cv_mpm" = "simple" -o "$apache_cv_mpm" = "winnt" ; then
        return 0
    else
        return 1
    fi
}

dnl No such check for a shared MPM.
ap_mpm_is_experimental ()
{
    if test "$apache_cv_mpm" = "event"; then
        return 0
    else
        return 1
    fi
}

if ap_mpm_is_threaded; then
  APR_CHECK_APR_DEFINE(APR_HAS_THREADS)

  if test "x$ac_cv_define_APR_HAS_THREADS" = "xno"; then
    AC_MSG_RESULT(The currently selected MPM requires threads which your system seems to lack)
    AC_MSG_CHECKING(checking for replacement)
    AC_MSG_RESULT(prefork selected)
    apache_cv_mpm=prefork
  else
    case $host in
      *-linux-*)
        case `uname -r` in
          2.0* )
            dnl Threaded MPM's are not supported on Linux 2.0
            dnl as on 2.0 the linuxthreads library uses SIGUSR1
            dnl and SIGUSR2 internally
            echo "Threaded MPM's are not supported on this platform"
            AC_MSG_CHECKING(checking for replacement)
            AC_MSG_RESULT(prefork selected)
            apache_cv_mpm=prefork
          ;;
        esac
      ;;
    esac
  fi
fi

APACHE_FAST_OUTPUT(server/mpm/Makefile)

if test "$apache_cv_mpm" = "shared"; then
  MPM_NAME=""
  MPM_SUBDIR_NAME=""
  MPM_LIB=""
  MPM_DIR=""
else
  MPM_NAME=$apache_cv_mpm
  if ap_mpm_is_experimental; then
    AC_MSG_WARN(You have selected an EXPERIMENTAL MPM.  Be warned!)
    MPM_SUBDIR_NAME=experimental/$MPM_NAME
  else
    MPM_SUBDIR_NAME=$MPM_NAME
  fi
  MPM_DIR=server/mpm/$MPM_SUBDIR_NAME
  MPM_LIB=$MPM_DIR/lib${MPM_NAME}.la

  APACHE_SUBST(MPM_NAME)
  APACHE_SUBST(MPM_SUBDIR_NAME)
  MODLIST="$MODLIST mpm_${MPM_NAME}"
fi

APACHE_SUBST(MPM_NAME)
APACHE_SUBST(MPM_SUBDIR_NAME)
