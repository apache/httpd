
APACHE_MODPATH_INIT(arch/unix)

if ap_mpm_is_enabled "simple" \
   || ap_mpm_is_enabled "worker" \
   || ap_mpm_is_enabled "event" \
   || ap_mpm_is_enabled "eventopt" \
   || ap_mpm_is_enabled "prefork"; then
    unixd_mods_enable=yes
else
    unixd_mods_enable=no
fi

APACHE_MODULE(unixd, unix specific support, , , $unixd_mods_enable)
APACHE_MODULE(privileges, Per-virtualhost Unix UserIDs and enhanced security for Solaris, , , no, [
  AC_CHECK_HEADERS(priv.h, [ap_HAVE_PRIV_H="yes"], [ap_HAVE_PRIV_H="no"])
  if test $ap_HAVE_PRIV_H = "no"; then
    AC_MSG_WARN([Your system does not support privileges.])
    enable_privileges="no"
  fi
])

APACHE_MODULE(systemd, Systemd support, , , all, [
  if test $ap_HAVE_SD_DAEMON_H = "no" || test -z "${SYSTEMD_LIBS}"; then
    AC_MSG_WARN([Your system does not support systemd.])
    enable_systemd="no"
  else
    APR_ADDTO(MOD_SYSTEMD_LDADD, [$SYSTEMD_LIBS])
    enable_systemd="yes"
  fi
])

APR_ADDTO(INCLUDES, [-I\$(top_srcdir)/$modpath_current])

APACHE_MODPATH_FINISH

