dnl modules enabled in this directory by default

APACHE_MODPATH_INIT(dav/fs)

dav_fs_objects="mod_dav_fs.lo dbm.lo lock.lo repos.lo"

if test "x$enable_dav" != "x"; then
  dav_fs_enable=$enable_dav
else
  dav_fs_enable=$dav_enable
fi

case "$host" in
  *os2*)
    # OS/2 DLLs must resolve all symbols at build time
    # and we need some from main DAV module
    dav_fs_objects="$dav_fs_objects ../main/mod_dav.la"
    ;;
esac

APACHE_MODULE(dav_fs, DAV provider for the filesystem.  --enable-dav also enables mod_dav_fs., $dav_fs_objects, , $dav_fs_enable,,dav)

APACHE_MODPATH_FINISH
