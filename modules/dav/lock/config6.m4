dnl modules enabled in this directory by default

APACHE_MODPATH_INIT(dav/lock)

dav_lock_objects="mod_dav_lock.lo locks.lo"

if test "x$enable_dav" != "x"; then
  dav_lock_enable=$enable_dav
else
  dav_lock_enable=$dav_enable
fi

case "$host" in
  *os2*)
    # OS/2 DLLs must resolve all symbols at build time
    # and we need some from main DAV module
    dav_lock_objects="$dav_lock_objects ../main/mod_dav.la"
    ;;
esac

APACHE_MODULE(dav_lock, DAV provider for generic locking, $dav_lock_objects, , $dav_lock_enable)

APACHE_MODPATH_FINISH
