

htpasswd_LTFLAGS=""
htdigest_LTFLAGS=""
rotatelogs_LTFLAGS=""
logresolve_LTFLAGS=""
ab_LTFLAGS=""

dnl XXX Should we change the foo_LTFLAGS="-static" settings below
dnl to something like APR_ADDTO? -aaron

AC_ARG_ENABLE(static-htpasswd,APACHE_HELP_STRING(--enable-static-htpasswd,Build a statically linked version of htpasswd),[
if test "$enableval" = "yes" ; then
  htpasswd_LTFLAGS="-static"
fi
])
APACHE_SUBST(htpasswd_LTFLAGS)

AC_ARG_ENABLE(static-htdigest,APACHE_HELP_STRING(--enable-static-htdigest,Build a statically linked version of htdigest),[
if test "$enableval" = "yes" ; then
  htdigest_LTFLAGS="-static"
fi
])
APACHE_SUBST(htdigest_LTFLAGS)

AC_ARG_ENABLE(static-rotatelogs,APACHE_HELP_STRING(--enable-static-rotatelogs,Build a statically linked version of rotatelogs),[
if test "$enableval" = "yes" ; then
  rotatelogs_LTFLAGS="-static"
fi
])
APACHE_SUBST(rotatelogs_LTFLAGS)

AC_ARG_ENABLE(static-logresolve,APACHE_HELP_STRING(--enable-static-logresolve,Build a statically linked version of logresolve),[
if test "$enableval" = "yes" ; then
  logresolve_LTFLAGS="-static"
fi
])
APACHE_SUBST(logresolve_LTFLAGS)

AC_ARG_ENABLE(static-ab,APACHE_HELP_STRING(--enable-static-ab,Build a statically linked version of ab),[
if test "$enableval" = "yes" ; then
  ab_LTFLAGS="-static"
fi
])
APACHE_SUBST(ab_LTFLAGS)
