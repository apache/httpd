dnl modules enabled in this directory by default
default_env=yes
default_log_config=yes

STANDARD_LIBS=""
AC_DEFUN(STANDARD_MODULE,[
  APACHE_MODULE($1)
  STANDARD_LIBS="$STANDARD_LIBS libapachemod_$1.la"
])

dnl XXX - Need to add help text to --enable-module flags
dnl XXX - Need to add support for per-module config
AC_DEFUN(APACHE_CHECK_STANDARD_MODULE, [
    AC_MSG_CHECKING([whether to enable mod_$1])
    AC_ARG_ENABLE(patsubst([$1], _, -), [  --enable-]patsubst([$1], _, -), [],
        [enable_$1=$default_$1])
    if test "$enable_[$1]" != "no" ; then
        MODLIST="$MODLIST ifelse([$2], , [$1], [$2])"
        STANDARD_MODULE([$1])
    fi
    AC_MSG_RESULT([$enable_$1])
])

APACHE_CHECK_STANDARD_MODULE(env)
APACHE_CHECK_STANDARD_MODULE(log_config, config_log)

dnl ## mod_usertrack.c
AC_CHECK_HEADERS(sys/times.h)
AC_CHECK_FUNCS(times)

MODLIST="$MODLIST mime negotiation includes autoindex dir cgi asis imap action userdir alias access auth setenvif echo"
STANDARD_MODULE(standard)

AC_SUBST(STANDARD_LIBS)
