dnl modules enabled in this directory by default

APACHE_MODPATH_INIT(dav/lock)

dav_lock_objects="mod_dav_lock.lo locks.lo"

APACHE_MODULE(dav_lock, DAV provider for generic locking, $dav_lock_objects, , no)

APACHE_MODPATH_FINISH
