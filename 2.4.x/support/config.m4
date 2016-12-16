htpasswd_LTFLAGS=""
htdigest_LTFLAGS=""
rotatelogs_LTFLAGS=""
logresolve_LTFLAGS=""
htdbm_LTFLAGS=""
ab_LTFLAGS=""
checkgid_LTFLAGS=""
htcacheclean_LTFLAGS=""
httxt2dbm_LTFLAGS=""
fcgistarter_LTFLAGS=""

AC_ARG_ENABLE(static-support,APACHE_HELP_STRING(--enable-static-support,Build a statically linked version of the support binaries),[
if test "$enableval" = "yes" ; then
  APR_ADDTO(htpasswd_LTFLAGS, [-static])
  APR_ADDTO(htdigest_LTFLAGS, [-static])
  APR_ADDTO(rotatelogs_LTFLAGS, [-static])
  APR_ADDTO(logresolve_LTFLAGS, [-static])
  APR_ADDTO(htdbm_LTFLAGS, [-static])
  APR_ADDTO(ab_LTFLAGS, [-static])
  APR_ADDTO(checkgid_LTFLAGS, [-static])
  APR_ADDTO(htcacheclean_LTFLAGS, [-static])
  APR_ADDTO(httxt2dbm_LTFLAGS, [-static])
  APR_ADDTO(fcgistarter_LTFLAGS, [-static])
fi
])

AC_ARG_ENABLE(static-htpasswd,APACHE_HELP_STRING(--enable-static-htpasswd,Build a statically linked version of htpasswd),[
if test "$enableval" = "yes" ; then
  APR_ADDTO(htpasswd_LTFLAGS, [-static])
else
  APR_REMOVEFROM(htpasswd_LTFLAGS, [-static])
fi
])
APACHE_SUBST(htpasswd_LTFLAGS)

AC_ARG_ENABLE(static-htdigest,APACHE_HELP_STRING(--enable-static-htdigest,Build a statically linked version of htdigest),[
if test "$enableval" = "yes" ; then
  APR_ADDTO(htdigest_LTFLAGS, [-static])
else
  APR_REMOVEFROM(htdigest_LTFLAGS, [-static])
fi
])
APACHE_SUBST(htdigest_LTFLAGS)

AC_ARG_ENABLE(static-rotatelogs,APACHE_HELP_STRING(--enable-static-rotatelogs,Build a statically linked version of rotatelogs),[
if test "$enableval" = "yes" ; then
  APR_ADDTO(rotatelogs_LTFLAGS, [-static])
else
  APR_REMOVEFROM(rotatelogs_LTFLAGS, [-static])
fi
])
APACHE_SUBST(rotatelogs_LTFLAGS)

AC_ARG_ENABLE(static-logresolve,APACHE_HELP_STRING(--enable-static-logresolve,Build a statically linked version of logresolve),[
if test "$enableval" = "yes" ; then
  APR_ADDTO(logresolve_LTFLAGS, [-static])
else
  APR_REMOVEFROM(logresolve_LTFLAGS, [-static])
fi
])
APACHE_SUBST(logresolve_LTFLAGS)

AC_ARG_ENABLE(static-htdbm,APACHE_HELP_STRING(--enable-static-htdbm,Build a statically linked version of htdbm),[
if test "$enableval" = "yes" ; then
  APR_ADDTO(htdbm_LTFLAGS, [-static])
else
  APR_REMOVEFROM(htdbm_LTFLAGS, [-static])
fi
])
APACHE_SUBST(htdbm_LTFLAGS)

AC_ARG_ENABLE(static-ab,APACHE_HELP_STRING(--enable-static-ab,Build a statically linked version of ab),[
if test "$enableval" = "yes" ; then
  APR_ADDTO(ab_LTFLAGS, [-static])
else
  APR_REMOVEFROM(ab_LTFLAGS, [-static])
fi
])
APACHE_SUBST(ab_LTFLAGS)

AC_ARG_ENABLE(static-checkgid,APACHE_HELP_STRING(--enable-static-checkgid,Build a statically linked version of checkgid),[
if test "$enableval" = "yes" ; then
  APR_ADDTO(checkgid_LTFLAGS, [-static])
else
  APR_REMOVEFROM(checkgid_LTFLAGS, [-static])
fi
])
APACHE_SUBST(checkgid_LTFLAGS)

AC_ARG_ENABLE(static-htcacheclean,APACHE_HELP_STRING(--enable-static-htcacheclean,Build a statically linked version of htcacheclean),[
if test "$enableval" = "yes" ; then
  APR_ADDTO(htcacheclean_LTFLAGS, [-static])
else
  APR_REMOVEFROM(htcacheclean_LTFLAGS, [-static])
fi
])
APACHE_SUBST(htcacheclean_LTFLAGS)

AC_ARG_ENABLE(static-httxt2dbm,APACHE_HELP_STRING(--enable-static-httxt2dbm,Build a statically linked version of httxt2dbm),[
if test "$enableval" = "yes" ; then
  APR_ADDTO(httxt2dbm_LTFLAGS, [-static])
else
  APR_REMOVEFROM(httxt2dbm, [-static])
fi
])
APACHE_SUBST(httxt2dbm_LTFLAGS)

AC_ARG_ENABLE(static-fcgistarter,APACHE_HELP_STRING(--enable-static-fcgistarter,Build a statically linked version of fcgistarter),[
if test "$enableval" = "yes" ; then
  APR_ADDTO(fcgistarter_LTFLAGS, [-static])
else
  APR_REMOVEFROM(fcgistarter, [-static])
fi
])
APACHE_SUBST(fcgistarter_LTFLAGS)

# Configure or check which of the non-portable support programs can be enabled.

NONPORTABLE_SUPPORT=""
case $host in
    *mingw*)
        ;;
    *)
        NONPORTABLE_SUPPORT="checkgid fcgistarter"
        ;;
esac
APACHE_SUBST(NONPORTABLE_SUPPORT)

# Configure the ulimit -n command used by apachectl.

case $host in
    *aix*)
        # this works in any locale, unlike the default command below, which
        # fails in a non-English locale if the hard limit is unlimited
        # since the display of the limit will translate "unlimited", but
        # ulimit only accepts English "unlimited" on input
        APACHECTL_ULIMIT="ulimit -S -n unlimited"
        ;;
    *alpha*-dec-osf*)
        # Tru64: -H is for setting, not retrieving
        APACHECTL_ULIMIT="ulimit -S -n \`ulimit -h -n\`"
        ;;
    *)
        if TMP_ULIMIT=`ulimit -H -n` && ulimit -S -n $TMP_ULIMIT >/dev/null 2>&1; then
            APACHECTL_ULIMIT="ulimit -S -n \`ulimit -H -n\`"
        else
            APACHECTL_ULIMIT=""
        fi
        ;;
esac
APACHE_SUBST(APACHECTL_ULIMIT)
