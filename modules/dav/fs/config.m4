dnl modules enabled in this directory by default

APACHE_MODPATH_INIT(dav/fs)

dnl ### we want to default this based on whether dav is being used...
dnl ### but there is no ordering to the config.m4 files right now...
APACHE_MODULE(dav_fs, DAV provider for the filesystem, , , no)
if test "$enable_dav_fs" = "yes"; then
  apache_need_sdbm=yes
fi

APACHE_MODPATH_FINISH
