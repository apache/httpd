
APACHE_MODPATH_INIT(experimental)

if test "$ac_cv_ebcdic" = "yes"; then
# mod_charset_lite can be very useful on an ebcdic system, 
#   so include it by default
    APACHE_MODULE(charset_lite, character set translation, , , yes)
else
    APACHE_MODULE(charset_lite, character set translation, , , no)
fi

dnl #  list of object files for mod_cache
cache_objs="dnl
mod_cache.lo dnl
cache_storage.lo dnl
cache_util.lo dnl
" 
APACHE_MODULE(cache, dynamic file caching, $cache_objs, , no)
APACHE_MODULE(disk_cache, disk caching module, , , no)
APACHE_MODULE(mem_cache, memory caching module, , , no)
APACHE_MODULE(example, example and demo module, , , no)
APACHE_MODULE(ext_filter, external filter module, , , no)
APACHE_MODULE(case_filter, example uppercase conversion filter, , , no)
APACHE_MODULE(case_filter_in, example uppercase conversion input filter, , , no)

APACHE_MODULE(deflate, Deflate transfer encoding support, , , no, [
  AC_ARG_WITH(z, APACHE_HELP_STRING(--with-z=DIR,use a specific zlib library),
  [
    if test "x$withval" != "xyes" && test "x$withval" != "x"; then
      ap_zlib_base="$withval"
    fi
  ])
  if test "x$ap_zlib_base" = "x"; then
    AC_MSG_CHECKING([for zlib location])
    AC_CACHE_VAL(ap_cv_zlib,[
      for dir in /usr/local /usr ; do
        if test -d $dir && test -f $dir/include/zlib.h; then
          ap_cv_zlib=$dir
          break
        fi
      done
    ])
    ap_zlib_base=$ap_cv_zlib
    if test "x$ap_zlib_base" = "x"; then
      enable_deflate=no
      AC_MSG_RESULT([not found])
    else
      AC_MSG_RESULT([$ap_zlib_base])
    fi
  fi
  if test "$enable_deflate" != "no"; then
    ap_save_includes=$INCLUDE
    ap_save_ldflags=$LDFLAGS
    ap_save_libs=$LIBS
    if test "$ap_zlib_base" != "/usr"; then
      APR_ADDTO(CPPFLAGS, [-I${ap_zlib_base}/include])
      APR_ADDTO(LDFLAGS, [-L${ap_zlib_base}/lib])
      if test "x$ap_platform_runtime_link_flag" != "x"; then
         APR_ADDTO(LDFLAGS, [$ap_platform_runtime_link_flag${ap_zlib_Base}/lib])
      fi
    fi
    APR_ADDTO(LIBS, [-lz])
    AC_MSG_CHECKING([for zlib library])
    AC_TRY_LINK([#include <zlib.h>], [return Z_OK;], 
    [AC_MSG_RESULT(found) 
     AC_CHECK_HEADERS(zutil.h)],
    [AC_MSG_RESULT(not found)
     enable_deflate=no
     INCLUDES=$ap_save_includes
     LDFLAGS=$ap_save_ldflags
     LIBS=$ap_save_libs])
  fi
])

APACHE_MODPATH_FINISH
