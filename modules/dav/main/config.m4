dnl modules enabled in this directory by default

APACHE_MODPATH_INIT(dav/main)

dav_objects="mod_dav.lo props.lo util.lo util_lock.lo liveprop.lo providers.lo std_liveprop.lo"

APACHE_MODULE(dav, WebDAV protocol handling, $dav_objects, , most)

if test "$enable_dav" != "no"; then
  apache_need_expat=yes

  INCLUDES="$INCLUDES -I\$(top_srcdir)/$modpath_current"
fi


APACHE_MODPATH_FINISH
