dnl modules enabled in this directory by default

dnl APACHE_MODULE(name, helptext[, objects[, structname[, default[, config]]]])

APACHE_MODPATH_INIT(cache)

APACHE_MODULE(file_cache, File cache, , , most)

dnl #  list of object files for mod_cache
cache_objs="dnl
mod_cache.lo dnl
cache_storage.lo dnl
cache_util.lo dnl
"
APACHE_MODULE(cache, dynamic file caching, $cache_objs, , most)
APACHE_MODULE(disk_cache, disk caching module, , , most)

AC_DEFUN([CHECK_DISTCACHE], [
  AC_CHECK_HEADER(
    [distcache/dc_client.h],
    [have_distcache=yes],
    [have_distcache=no])
  if test "$have_distcache" = "yes"; then
    AC_MSG_CHECKING(for Distcache version)
    AC_TRY_COMPILE(
[#include <distcache/dc_client.h>],
[#if DISTCACHE_CLIENT_API != 0x0001
#error "distcache API version is unrecognised"
#endif],
[],
[have_distcache=no])
    AC_MSG_RESULT($have_distcache)
  fi
  if test "$have_distcache" = "yes"; then
    AC_MSG_CHECKING(for Distcache libraries)
    save_libs=$LIBS
    LIBS="$LIBS -ldistcache -lnal"
    AC_TRY_LINK(
      [#include <distcache/dc_client.h>],
      [DC_CTX *foo = DC_CTX_new((const char *)0,0);],
      [],
      [have_distcache=no])
    LIBS=$save_libs
    AC_MSG_RESULT($have_distcache)
  fi
  if test "$have_distcache" = "yes"; then
    APR_ADDTO(MOD_SOCACHE_LDADD, [-ldistcache -lnal])
    AC_DEFINE(HAVE_DISTCACHE, 1, [Define if distcache support is enabled])
  else
    enable_socache_dc=no
  fi
])

APACHE_MODULE(socache_shmcb,  shmcb small object cache provider, , , most)
APACHE_MODULE(socache_dbm, dbm small object cache provider, , , most)
APACHE_MODULE(socache_memcache, memcache small object cache provider, , , most)
APACHE_MODULE(socache_dc, distcache small object cache provider, , , no, [
   CHECK_DISTCACHE
])

APR_ADDTO(INCLUDES, [-I\$(top_srcdir)/$modpath_current])

APACHE_MODPATH_FINISH
