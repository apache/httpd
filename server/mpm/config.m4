AC_MSG_CHECKING(which MPM to use)
AC_ARG_WITH(mpm,
[  --with-mpm=MPM          Choose the process model for Apache to use.
                          MPM={dexter,mpmt_beos,mpmt_pthread,prefork,spmt_os2}],[
  APACHE_MPM=$withval
],[
  APACHE_MPM=mpmt_pthread
  case "`uname -sr`" in
    "BeOS"*)
      APACHE_MPM=mpmt_beos;;
    "OS/2"*)
      APACHE_MPM=spmt_os2;;
  esac 
])
AC_MSG_RESULT($APACHE_MPM)

apache_cv_mpm=$APACHE_MPM
	
if test "$apache_cv_mpm" = "mpmt_pthread" -o "$apache_cv_mpm" = "dexter"; then
  PTHREADS_CHECK
  AC_MSG_CHECKING([for which threading library to use])
  AC_MSG_RESULT($threads_result)

  if test "$apache_threads_working" = "no"; then
    AC_MSG_RESULT(The currently selected MPM requires pthreads which your system seems to lack)
    AC_MSG_CHECKING(checking for replacement)
    AC_MSG_RESULT(prefork selected)
    apache_cv_mpm=prefork
  fi
fi

APACHE_CHECK_SHM_RW

APACHE_FAST_OUTPUT(modules/mpm/Makefile)
MPM_NAME=$apache_cv_mpm
MPM_DIR=modules/mpm/$MPM_NAME
MPM_LIB=$MPM_DIR/lib${MPM_NAME}.la

APACHE_SUBST(MPM_NAME)
MODLIST="$MODLIST mpm_${MPM_NAME}"

dnl All the unix MPMs use shared memory; save a little duplication
AC_DEFUN(APACHE_MPM_CHECK_SHMEM, [
    AC_CHECK_FUNCS(shmget)
    AC_FUNC_MMAP
    
    AC_MSG_CHECKING(which shared memory mechanism to use)
    if test "$ac_cv_func_shmget" = "yes" ; then
        AC_DEFINE(USE_SHMGET_SCOREBOARD,,
            [Define if MPMs should use shmget to implement their shared memory])
        AC_MSG_RESULT(shmget)
    elif test "$ac_cv_func_mmap" = "yes" ; then
        AC_DEFINE(USE_MMAP_SCOREBOARD,,
            [Define if MPMs should use mmap to implement their shared memory])
        AC_MSG_RESULT(mmap)
    else
        AC_MSG_ERROR(No known shared memory system)
    fi
])

dnl Check for pthreads and attempt to support it
AC_DEFUN(APACHE_MPM_PTHREAD, [

dnl XXX - We should be checking for the proper flags to use on a particular 
dnl platform. This will cover a couple of them, anyway

    AC_CHECK_HEADER(pthread.h, [ ],[
        AC_MSG_ERROR(This MPM requires pthreads. Try --with-mpm=prefork.)
    ])
    AC_CHECK_FUNC(pthread_create, [ ],[
        AC_MSG_ERROR(Can't compile pthread code.)
    ])

    dnl User threads libraries need pthread.h included everywhere
    AC_DEFINE(PTHREAD_EVERYWHERE,,
        [Define if all code should have #include <pthread.h>])
])
