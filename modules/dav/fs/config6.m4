dnl modules enabled in this directory by default

APACHE_MODPATH_INIT(dav/fs)

dav_fs_objects="mod_dav_fs.lo dbm.lo lock.lo repos.lo"

if test "x$enable_dav" != "x"; then
  dav_fs_enable=$enable_dav
else
  dav_fs_enable=$dav_enable
fi

APACHE_MODULE(dav_fs, DAV provider for the filesystem, $dav_fs_objects, , $dav_fs_enable)

APACHE_MODPATH_FINISH
