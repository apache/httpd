AC_MSG_CHECKING(which MPM to use)
AC_ARG_WITH(mpm,
APACHE_HELP_STRING(--with-mpm=MPM,Choose the process model for Apache to use.
                          MPM={beos|worker|prefork|spmt_os2|perchild}),[
  APACHE_MPM=$withval
],[
  if test "x$APACHE_MPM" = "x"; then
    APACHE_MPM=prefork
  fi
])
AC_MSG_RESULT($APACHE_MPM)

apache_cv_mpm=$APACHE_MPM
	
if test "$apache_cv_mpm" = "worker" -o "$apache_cv_mpm" = "perchild"; then
  APR_CHECK_APR_DEFINE(APR_HAS_THREADS, srclib/apr)

  if test "x$ac_cv_define_APR_HAS_THREADS" = "xno"; then
    AC_MSG_RESULT(The currently selected MPM requires threads which your system seems to lack)
    AC_MSG_CHECKING(checking for replacement)
    AC_MSG_RESULT(prefork selected)
    apache_cv_mpm=prefork
  fi
fi
if test ! -f "$abs_srcdir/server/mpm/$apache_cv_mpm/mpm.h"; then
    AC_MSG_ERROR(the selected mpm -- $apache_cv_mpm -- is not supported)
fi

APACHE_FAST_OUTPUT(server/mpm/Makefile)

MPM_NAME=$apache_cv_mpm
MPM_DIR=server/mpm/$MPM_NAME
MPM_LIB=$MPM_DIR/lib${MPM_NAME}.la

APACHE_SUBST(MPM_NAME)
MODLIST="$MODLIST mpm_${MPM_NAME}"

