AC_MSG_CHECKING(if prefork MPM supports this platform)
if test $forking_mpms_supported != yes; then
    AC_MSG_RESULT(no - This is not a forking platform)
else
    AC_MSG_RESULT(yes)
    APACHE_MPM_SUPPORTED(prefork, yes, no)
fi
