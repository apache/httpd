
dnl ## mod_usertrack.c
AC_CHECK_HEADERS(sys/times.h)
AC_CHECK_FUNCS(times)

MODLIST="$MODLIST env config_log mime negotiation includes autoindex dir cgi asis imap action userdir alias access auth setenvif echo"
APACHE_MODULE(standard)
