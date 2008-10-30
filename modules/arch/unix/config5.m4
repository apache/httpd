
APACHE_MODPATH_INIT(arch/unix)


if test "$APACHE_MPM" = "simple" ; then
  unixd_mods_enable=yes
else
  unixd_mods_enable=no
fi

APACHE_MODULE(unixd, unix specific support, , , $unixd_mods_enable)

APACHE_MODPATH_FINISH

