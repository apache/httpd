dnl
dnl APR_PRELOAD
dnl
dnl  Preload various ENV/makefile paramsm such as CC, CFLAGS, etc
dnl  based on outside knowledge
dnl
AC_DEFUN(APACHE_PRELOAD, [
if test "$DID_APACHE_PRELOAD" = "yes" ; then

  echo "Apache hints file rules for $host already applied"

else

  DID_APACHE_PRELOAD="yes"; export DID_APACHE_PRELOAD

  echo "Applying Apache hints file rules for $host"

  case "$host" in
    *-apple-aux3*)
	APR_SETVAR(APACHE_MPM, [prefork])
        APR_SETVAR(SINGLE_LISTEN_UNSERIALIZED_ACCEPT, [1])
	;;
    *os2_emx*)
        APR_SETVAR(APACHE_MPM, [spmt_os2])
        APR_SETVAR(SINGLE_LISTEN_UNSERIALIZED_ACCEPT, [1])
	;;
    *-linux-*)
        case `uname -r` in
	    2.2* ) APR_SETVAR(SINGLE_LISTEN_UNSERIALIZED_ACCEPT, [1])
	           ;;
	    * )
	           ;;
        esac
	;;
    *486-*-bsdi*)
        APR_SETVAR(SINGLE_LISTEN_UNSERIALIZED_ACCEPT, [1])
	;;
    *-netbsd*)
        APR_SETVAR(SINGLE_LISTEN_UNSERIALIZED_ACCEPT, [1])
	;;
    *-freebsd*)
        APR_SETVAR(SINGLE_LISTEN_UNSERIALIZED_ACCEPT, [1])
	;;
dnl    *-apple-rhapsody*)
dnl     APR_SETVAR(SINGLE_LISTEN_UNSERIALIZED_ACCEPT, [1])
dnl	;;
    *-apple-darwin*)
        APR_SETVAR(SINGLE_LISTEN_UNSERIALIZED_ACCEPT, [1])
	;;
    *-dec-osf*)
        APR_SETVAR(SINGLE_LISTEN_UNSERIALIZED_ACCEPT, [1])
	;;
    *-qnx)
        APR_SETVAR(SINGLE_LISTEN_UNSERIALIZED_ACCEPT, [1])
	;;
    *-beos*)
        APR_SETVAR(APACHE_MPM, [beos])
        APR_SETVAR(SINGLE_LISTEN_UNSERIALIZED_ACCEPT, [1])
        ;;
  esac

fi
])
