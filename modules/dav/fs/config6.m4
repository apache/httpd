dnl modules enabled in this directory by default

APACHE_MODPATH_INIT(dav/fs)

dav_fs_objects="mod_dav_fs.lo dbm.lo lock.lo repos.lo"

if test "$enable_dav" = "no"; then
  dav_fs_enable=no
else
  dav_fs_enable=yes
fi

APACHE_MODULE(dav_fs, DAV provider for the filesystem, $dav_fs_objects, , $dav_fs_enable)

APACHE_MODPATH_FINISH
