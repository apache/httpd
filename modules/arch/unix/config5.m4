
APACHE_MODPATH_INIT(arch/unix)


if test "$APACHE_MPM" = "simple" -o "$APACHE_MPM" = "worker" \
   -o i"$APACHE_MPM" = "event" -o "$APACHE_MPM" = "prefork" ; then
  unixd_mods_enable=yes
else
  unixd_mods_enable=no
fi

APACHE_MODULE(unixd, unix specific support, , , $unixd_mods_enable)
APACHE_MODULE(privileges, Per-virtualhost Unix UserIDs and enhanced security for Solaris)

APACHE_MODPATH_FINISH

