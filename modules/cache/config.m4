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
cache_disk_objs="mod_cache_disk.lo"
cache_socache_objs="mod_cache_socache.lo"

case "$host" in
  *os2*)
    # OS/2 DLLs must resolve all symbols at build time
    # and we need some from main cache module
    cache_disk_objs="$cache_disk_objs mod_cache.la"
    cache_socache_objs="$cache_socache_objs mod_cache.la"
    ;;
esac

APACHE_MODULE(cache, dynamic file caching.  At least one storage management module (e.g. mod_cache_disk) is also necessary., $cache_objs, , most)
APACHE_MODULE(cache_disk, disk caching module, $cache_disk_objs, , most, , cache)
APACHE_MODULE(cache_socache, shared object caching module, $cache_socache_objs, , most)

dnl
dnl APACHE_CHECK_DISTCACHE
dnl
dnl Configure for the detected distcache installation, giving
dnl preference to "--with-distcache=<path>" if it was specified.
dnl
AC_DEFUN(APACHE_CHECK_DISTCACHE,[
if test "x$ap_distcache_configured" = "x"; then
  dnl initialise the variables we use
  ap_distcache_found=""
  ap_distcache_base=""
  ap_distcache_libs=""
  ap_distcache_ldflags=""
  ap_distcache_with=""

  dnl Determine the distcache base directory, if any
  AC_MSG_CHECKING([for user-provided distcache base])
  AC_ARG_WITH(distcache, APACHE_HELP_STRING(--with-distcache=PATH, Distcache installation directory), [
    dnl If --with-distcache specifies a directory, we use that directory or fail
    if test "x$withval" != "xyes" -a "x$withval" != "x"; then
      dnl This ensures $withval is actually a directory and that it is absolute
      ap_distcache_with="yes"
      ap_distcache_base="`cd $withval ; pwd`"
    fi
  ])
  if test "x$ap_distcache_base" = "x"; then
    AC_MSG_RESULT(none)
  else
    AC_MSG_RESULT($ap_distcache_base)
  fi

  dnl Run header and version checks
  saved_CPPFLAGS="$CPPFLAGS"
  saved_LIBS="$LIBS"
  saved_LDFLAGS="$LDFLAGS"

  if test "x$ap_distcache_base" != "x"; then
    APR_ADDTO(CPPFLAGS, [-I$ap_distcache_base/include])
    APR_ADDTO(MOD_INCLUDES, [-I$ap_distcache_base/include])
    APR_ADDTO(LDFLAGS, [-L$ap_distcache_base/lib])
    APR_ADDTO(ap_distcache_ldflags, [-L$ap_distcache_base/lib])
    if test "x$ap_platform_runtime_link_flag" != "x"; then
      APR_ADDTO(LDFLAGS, [$ap_platform_runtime_link_flag$ap_distcache_base/lib])
      APR_ADDTO(ap_distcache_ldflags, [$ap_platform_runtime_link_flag$ap_distcache_base/lib])
    fi
  fi
  dnl First check for mandatory headers
  AC_CHECK_HEADERS([distcache/dc_client.h], [ap_distcache_found="yes"], [])
  if test "$ap_distcache_found" = "yes"; then
    dnl test for a good version
    AC_MSG_CHECKING(for distcache version)
    AC_TRY_COMPILE([#include <distcache/dc_client.h>],[
#if DISTCACHE_CLIENT_API != 0x0001
#error "distcache API version is unrecognised"
#endif],
      [],
      [ap_distcache_found="no"])
    AC_MSG_RESULT($ap_distcache_found)
  fi
  if test "$ap_distcache_found" != "yes"; then
    if test "x$ap_distcache_with" = "x"; then
      AC_MSG_WARN([...No distcache detected])
    else
      AC_MSG_ERROR([...No distcache detected])
    fi
  else
    dnl Run library and function checks
    AC_MSG_CHECKING(for distcache libraries)
    ap_distcache_libs="-ldistcache -lnal"
    APR_ADDTO(LIBS, [$ap_distcache_libs])

    AC_TRY_LINK(
      [#include <distcache/dc_client.h>],
      [DC_CTX *foo = DC_CTX_new((const char *)0,0);],
      [],
      [ap_distcache_found="no"])
    AC_MSG_RESULT($ap_distcache_found)
    if test "$ap_distcache_found" != "yes"; then
      if test "x$ap_distcache_base" = "x"; then
        AC_MSG_WARN([... Error, distcache libraries were missing or unusable])
      else
        AC_MSG_ERROR([... Error, distcache libraries were missing or unusable])
      fi
    fi
  fi

  dnl restore
  CPPFLAGS="$saved_CPPFLAGS"
  LIBS="$saved_LIBS"
  LDFLAGS="$saved_LDFLAGS"

  dnl Adjust apache's configuration based on what we found above.
  if test "$ap_distcache_found" = "yes"; then
    APR_ADDTO(MOD_SOCACHE_DC_LDADD, [$ap_distcache_ldflags $ap_distcache_libs])
    AC_DEFINE(HAVE_DISTCACHE, 1, [Define if distcache support is enabled])
  else
    enable_socache_dc=no
  fi
  ap_distcache_configured="yes"
fi
])

APACHE_MODULE(socache_shmcb,  shmcb small object cache provider, , , most)
APACHE_MODULE(socache_dbm, dbm small object cache provider, , , most)
APACHE_MODULE(socache_memcache, memcache small object cache provider, , , most)
APACHE_MODULE(socache_dc, distcache small object cache provider, , , no, [
    APACHE_CHECK_DISTCACHE
])

APR_ADDTO(INCLUDES, [-I\$(top_srcdir)/$modpath_current])

APACHE_MODPATH_FINISH
