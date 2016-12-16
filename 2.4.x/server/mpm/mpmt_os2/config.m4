AC_MSG_CHECKING(if mpmt_os2 MPM supports this platform)
case $host in
    *os2-emx*)
        AC_MSG_RESULT(yes)
        APACHE_MPM_SUPPORTED(mpmt_os2, no, yes)
        ;;
    *)
        AC_MSG_RESULT(no)
        ;;
esac
