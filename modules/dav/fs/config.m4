dnl modules enabled in this directory by default

APACHE_MODPATH_INIT(dav/fs)

dav_fs_objects="mod_dav_fs.lo dbm.lo lock.lo repos.lo"

CFLAGS="$CFLAGS -I../main"

dnl ### we want to default this based on whether dav is being used...
dnl ### but there is no ordering to the config.m4 files right now...
APACHE_MODULE(dav_fs, DAV provider for the filesystem, $dav_fs_objects, , no)

APACHE_MODPATH_FINISH
