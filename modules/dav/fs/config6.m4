dnl modules enabled in this directory by default

APACHE_MODPATH_INIT(dav/fs)

dav_fs_objects="mod_dav_fs.lo dbm.lo lock.lo quota.lo repos.lo"

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

if test "x$enable_dav_fs" = "xshared"; then
    # The only symbol which needs to be exported is the module
    # structure, so ask libtool to hide everything else:
    APR_ADDTO(MOD_DAV_FS_LDADD, [-export-symbols-regex dav_fs_module])
fi

APACHE_MODPATH_FINISH
