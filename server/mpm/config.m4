AC_MSG_CHECKING(which MPM to use)
AC_ARG_WITH(mpm,
[  --with-mpm=MPM          Choose the process model, etc. for Apache to use.],
[
  if test "$withval" != "no" ; then
    apache_cv_mpm=$withval
    AC_MSG_RESULT($apache_cv_mpm)
  else
    AC_MSG_ERROR(An MPM must be specified)
  fi
],[
  AC_MSG_ERROR(An MPM must be specified)
])

APACHE_OUTPUT(modules/mpm/Makefile)
MPM_NAME=$apache_cv_mpm
MPM_DIR=modules/mpm/$MPM_NAME
MPM_LIB=$MPM_DIR/lib${MPM_NAME}.la

AC_SUBST(MPM_NAME)

dnl All the unix MPMs use shared memory; save a little duplication
AC_DEFUN(APACHE_MPM_CHECK_SHMEM, [
    AC_CHECK_FUNCS(shmget)
    AC_FUNC_MMAP
    
    AC_MSG_CHECKING(which shared memory mechanism to use)
    if test "$ac_cv_func_shmget" = "yes" ; then
        AC_DEFINE(USE_SHMGET_SCOREBOARD)
        AC_MSG_RESULT(shmget)
    elif test "$ac_cv_func_mmap" = "yes" ; then
        AC_DEFINE(USE_MMAP_SCOREBOARD)
        AC_MSG_RESULT(mmap)
    else
        AC_MSG_ERROR(No known shared memory system)
    fi
])

dnl Check for pthreads and attempt to support it
AC_DEFUN(APACHE_MPM_PTHREAD, [

dnl XXX - We should be checking for the proper flags to use on a particular 
dnl platform. This will cover a couple of them, anyway
    CFLAGS="-pthread $CFLAGS"
    CXXFLAGS="-pthread $CXXFLAGS"

    AC_CHECK_HEADER(pthread.h, [ ],[
        AC_MSG_ERROR(This MPM requires pthreads. Try --with-mpm=prefork.)
    ])
    AC_CHECK_FUNC(pthread_create, [ ],[
        AC_MSG_ERROR(Can't compile pthread code.)
    ])

    dnl User threads libraries need pthread.h included everywhere
    AC_DEFINE(PTHREAD_EVERYWHERE)
])
