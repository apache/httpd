dnl modules enabled in this directory by default

APACHE_MODPATH_INIT(dav/main)

APACHE_MODULE(dav, WebDAV protocol handling, \
	mod_dav.lo props.lo util.lo util_lock.lo opaquelock.lo liveprop.lo, \
	, no)

if test "$enable_dav" = "yes"; then
  apache_need_expat=yes

  INCLUDES="$INCLUDES -I\$(top_srcdir)/$modpath_current"
fi


APACHE_MODPATH_FINISH
