dnl modules enabled in this directory by default

APACHE_MODPATH_INIT(dav/fs)

dnl ### dav_fs is not a module, but we want to have it enabled/disabled
dnl ### like one. with a bit o' work, dav_fs *will* become a true module.

dnl ### this is snarfed from APACHE_MODULE. it does not allow dav_fs to be
dnl ### shared, and it does not add it into MODLIST. basically... it is
dnl ### just a static library to link into Apache at this point
AC_DEFUN(DAV_FS_MODULE,[
  AC_MSG_CHECKING(whether to enable mod_$1)
  define([optname],[  --]ifelse($5,yes,disable,enable)[-]translit($1,_,-))dnl
  AC_ARG_ENABLE(translit($1,_,-),optname() substr([                         ],len(optname()))$2,,enable_$1=ifelse($5,,no,$5))
  undefine([optname])dnl
  AC_MSG_RESULT($enable_$1)
  if test "$enable_$1" != "no"; then
    APACHE_MODPATH_ADD($1, , $3)
  fi
])dnl


dnl ### we want to default this based on whether dav is being used...
dnl ### but there is no ordering to the config.m4 files right now...
DAV_FS_MODULE(dav_fs, DAV provider for the filesystem, , , no)


if test "$enable_dav_fs" = "yes"; then
  apache_need_sdbm=yes
fi

APACHE_MODPATH_FINISH
