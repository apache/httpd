dnl modules enabled in this directory by default

dnl APACHE_MODULE(name, helptext[, objects[, structname[, default[, config]]]])

APACHE_MODPATH_INIT(filters)

APACHE_MODULE(ext_filter, external filter module, , , most)
APACHE_MODULE(include, Server Side Includes, , , yes)

APR_ADDTO(LT_LDFLAGS,-export-dynamic)

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
     AC_CHECK_HEADERS(zutil.h)],
    [AC_MSG_RESULT(not found)
     enable_deflate=no
     INCLUDES=$ap_save_includes
     LDFLAGS=$ap_save_ldflags
     LIBS=$ap_save_libs])
    CPPFLAGS=$ap_save_cppflags
  fi
])

APACHE_MODPATH_FINISH
