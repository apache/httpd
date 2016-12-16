AC_MSG_CHECKING(if WinNT MPM supports this platform)
case $host in
    *mingw32*)
        AC_MSG_RESULT(yes)
        APACHE_MPM_SUPPORTED(winnt, no, yes)
        ;;
    *)
        AC_MSG_RESULT(no)
        ;;
esac
