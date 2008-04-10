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
dnl #  list of object files for mod_mem_cache
mem_cache_objs="dnl
mod_mem_cache.lo dnl
cache_cache.lo dnl
cache_pqueue.lo dnl
cache_hash.lo dnl
cache_util.lo dnl
"
APACHE_MODULE(cache, dynamic file caching, $cache_objs, , most)
APACHE_MODULE(disk_cache, disk caching module, , , most)
APACHE_MODULE(mem_cache, memory caching module, $mem_cache_objs, , )

AC_DEFUN([CHECK_DISTCACHE], [
  AC_MSG_CHECKING(whether Distcache is required)
  ap_ssltk_dc="no"
  tmp_nomessage=""
  tmp_forced="no"
  AC_ARG_ENABLE(distcache,
    APACHE_HELP_STRING(--enable-distcache,Enable distcache support),
    ap_ssltk_dc="$enableval"
    tmp_nomessage=""
    tmp_forced="yes"
    if test "x$ap_ssltk_dc" = "x"; then
      ap_ssltk_dc="yes"
      dnl our "error"s become "tests revealed that..."
      tmp_forced="no"
    fi
    if test "$ap_ssltk_dc" != "yes" -a "$ap_ssltk_dc" != "no"; then
      tmp_nomessage="--enable-distcache had illegal syntax - disabling"
      ap_ssltk_dc="no"
    fi)
  if test "$tmp_forced" = "no"; then
    AC_MSG_RESULT($ap_ssltk_dc (default))
  else
    AC_MSG_RESULT($ap_ssltk_dc (specified))
  fi
  if test "$tmp_forced" = "yes" -a "x$ap_ssltk_dc" = "xno" -a "x$tmp_nomessage" != "x"; then
    AC_MSG_ERROR(distcache support failed: $tmp_nomessage)
  fi
  if test "$ap_ssltk_dc" = "yes"; then
    AC_CHECK_HEADER(
      [distcache/dc_client.h],
      [],
      [tmp_nomessage="can't include distcache headers"
      ap_ssltk_dc="no"])
    if test "$tmp_forced" = "yes" -a "x$ap_ssltk_dc" = "xno"; then
      AC_MSG_ERROR(distcache support failed: $tmp_nomessage)
    fi
  fi
  if test "$ap_ssltk_dc" = "yes"; then
    AC_MSG_CHECKING(for Distcache version)
    AC_TRY_COMPILE(
[#include <distcache/dc_client.h>],
[#if DISTCACHE_CLIENT_API != 0x0001
#error "distcache API version is unrecognised"
#endif],
[],
[tmp_nomessage="distcache has an unsupported API version"
ap_ssltk_dc="no"])
    AC_MSG_RESULT($ap_ssltk_dc)
    if test "$tmp_forced" = "yes" -a "x$ap_ssltk_dc" = "xno"; then
      AC_MSG_ERROR(distcache support failed: $tmp_nomessage)
    fi
  fi
  if test "$ap_ssltk_dc" = "yes"; then
    AC_MSG_CHECKING(for Distcache libraries)
    save_libs=$LIBS
    LIBS="$LIBS -ldistcache -lnal"
    AC_TRY_LINK(
      [#include <distcache/dc_client.h>],
      [DC_CTX *foo = DC_CTX_new((const char *)0,0);],
      [],
      [tmp_no_message="failed to link with distcache libraries"
      ap_ssltk_dc="no"])
    LIBS=$save_libs
    AC_MSG_RESULT($ap_ssltk_dc)
    if test "$tmp_forced" = "yes" -a "x$ap_ssltk_dc" = "xno"; then
      AC_MSG_ERROR(distcache support failed: $tmp_nomessage)
    else
      APR_ADDTO(MOD_SOCACHE_LDADD, [-ldistcache -lnal])
      AC_DEFINE(HAVE_DISTCACHE, 1, [Define if distcache support is enabled])
    fi
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
