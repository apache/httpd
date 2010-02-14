dnl modules enabled in this directory by default

dnl APACHE_MODULE(name, helptext[, objects[, structname[, default[, config]]]])

APACHE_MODPATH_INIT(filters)

APACHE_MODULE(buffer, Filter Buffering, , , yes)
APACHE_MODULE(ratelimit, Output Bandwidth Limiting, , , yes)
APACHE_MODULE(reqtimeout, Limit time waiting for request from client, , , yes)
APACHE_MODULE(ext_filter, external filter module, , , most)
APACHE_MODULE(request, Request Body Filtering, , , yes)
APACHE_MODULE(include, Server Side Includes, , , yes)
APACHE_MODULE(filter, Smart Filtering, , , yes)
APACHE_MODULE(reflector, Reflect request through the output filter stack, , , yes)
APACHE_MODULE(substitute, response content rewrite-like filtering, , , most)

sed_obj="mod_sed.lo sed0.lo sed1.lo regexp.lo"
APACHE_MODULE(sed, filter request and/or response bodies through sed, $sed_obj)

if test "$ac_cv_ebcdic" = "yes"; then
# mod_charset_lite can be very useful on an ebcdic system,
#   so include it by default
    APACHE_MODULE(charset_lite, character set translation, , , yes)
else
    APACHE_MODULE(charset_lite, character set translation, , , no)
fi


APACHE_MODULE(deflate, Deflate transfer encoding support, , , most, [
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
    ap_save_includes=$INCLUDES
    ap_save_ldflags=$LDFLAGS
    ap_save_cppflags=$CPPFLAGS
    if test "$ap_zlib_base" != "/usr"; then
      APR_ADDTO(INCLUDES, [-I${ap_zlib_base}/include])
      dnl put in CPPFLAGS temporarily so that AC_TRY_LINK below will work
      CPPFLAGS="$CPPFLAGS $INCLUDES"
      APR_ADDTO(LDFLAGS, [-L${ap_zlib_base}/lib])
      if test "x$ap_platform_runtime_link_flag" != "x"; then
         APR_ADDTO(LDFLAGS, [$ap_platform_runtime_link_flag${ap_zlib_base}/lib])
      fi
    fi
    APR_ADDTO(LIBS, [-lz])
    AC_MSG_CHECKING([for zlib library])
    AC_TRY_LINK([#include <zlib.h>], [int i = Z_OK;], 
    [AC_MSG_RESULT(found) 
     APR_SETVAR(MOD_DEFLATE_LDADD, [-lz])],
    [AC_MSG_RESULT(not found)
     enable_deflate=no
     INCLUDES=$ap_save_includes
     LDFLAGS=$ap_save_ldflags])
    APR_REMOVEFROM(LIBS, [-lz])
    CPPFLAGS=$ap_save_cppflags
  fi
])

APR_ADDTO(INCLUDES, [-I\$(top_srcdir)/$modpath_current])

APACHE_MODPATH_FINISH
