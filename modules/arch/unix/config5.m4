
APACHE_MODPATH_INIT(arch/unix)

if test "$APACHE_MPM" = "simple" -o "$APACHE_MPM" = "worker" \
   -o "$APACHE_MPM" = "event" -o "$APACHE_MPM" = "prefork" \
   -o "$APACHE_MPM" = "shared"; then
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

APACHE_MODPATH_FINISH

