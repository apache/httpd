dnl modules enabled in this directory by default

APACHE_MODPATH_INIT(dav/main)

APACHE_MODULE(dav, WebDAV protocol handling,
	mod_dav.lo props.lo util.lo util_lock.lo opaquelock.lo
	liveprop.lo
	, , no)

if test "$enable_dav" = "yes"; then
  apache_need_expat=yes

  INCLUDES="$INCLUDES -I\$(top_srcdir)/$modpath_current"
fi

dnl ### hack. we reference a symbol from the dav_fs "library", but that lib
dnl ### appears on the link line first. nothing refers to the variable, so
dnl ### it doesn't get sucked in. we will add the lib one more time *after*
dnl ### our location on the link line, so we pick the thing up.
if test "$enable_dav" = "yes"; then
  BUILTIN_LIBS="$BUILTIN_LIBS $modpath_current/../fs/libapachemod_dav_fs.la"
fi


APACHE_MODPATH_FINISH
