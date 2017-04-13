dnl modules enabled in this directory by default

dnl APACHE_MODULE(name, helptext[, objects[, structname[, default[, config]]]])

APACHE_MODPATH_INIT(filters)

APACHE_MODULE(buffer, Filter Buffering, , , most)
APACHE_MODULE(data, RFC2397 data encoder, , , )
APACHE_MODULE(ratelimit, Output Bandwidth Limiting, , , most)
APACHE_MODULE(reqtimeout, Limit time waiting for request from client, , , yes)
APACHE_MODULE(ext_filter, external filter module, , , most)
APACHE_MODULE(request, Request Body Filtering, , , most)
APACHE_MODULE(include, Server Side Includes, , , most)
APACHE_MODULE(filter, Smart Filtering, , , yes)
APACHE_MODULE(reflector, Reflect request through the output filter stack, , , )
APACHE_MODULE(substitute, response content rewrite-like filtering, , , most)

sed_obj="mod_sed.lo sed0.lo sed1.lo regexp.lo"
APACHE_MODULE(sed, filter request and/or response bodies through sed, $sed_obj, , most, [
    if test "x$enable_sed" = "xshared"; then
        # The only symbol which needs to be exported is the module
        # structure, so ask libtool to hide libsed internals:
        APR_ADDTO(MOD_SED_LDADD, [-export-symbols-regex sed_module])
    fi
])

if test "$ac_cv_ebcdic" = "yes"; then
# mod_charset_lite can be very useful on an ebcdic system,
#   so include it by default
    APACHE_MODULE(charset_lite, character set translation.  Enabled by default only on EBCDIC systems., , , yes)
else
    APACHE_MODULE(charset_lite, character set translation.  Enabled by default only on EBCDIC systems., , , )
fi


APACHE_MODULE(deflate, Deflate transfer encoding support, , , most, [
  AC_ARG_WITH(z, APACHE_HELP_STRING(--with-z=PATH,use a specific zlib library),
  [
    if test "x$withval" != "xyes" && test "x$withval" != "x"; then
      ap_zlib_base="$withval"
      ap_zlib_with="yes"
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
    ap_zlib_ldflags=""
    if test "$ap_zlib_base" != "/usr"; then
      APR_ADDTO(INCLUDES, [-I${ap_zlib_base}/include])
      APR_ADDTO(MOD_INCLUDES, [-I${ap_zlib_base}/include])
      dnl put in CPPFLAGS temporarily so that AC_TRY_LINK below will work
      CPPFLAGS="$CPPFLAGS $INCLUDES"
      APR_ADDTO(LDFLAGS, [-L${ap_zlib_base}/lib])
      APR_ADDTO(ap_zlib_ldflags, [-L${ap_zlib_base}/lib])
      if test "x$ap_platform_runtime_link_flag" != "x"; then
         APR_ADDTO(LDFLAGS, [$ap_platform_runtime_link_flag${ap_zlib_base}/lib])
         APR_ADDTO(ap_zlib_ldflags, [$ap_platform_runtime_link_flag${ap_zlib_base}/lib])
      fi
    fi
    APR_ADDTO(LIBS, [-lz])
    AC_MSG_CHECKING([for zlib library])
    AC_TRY_LINK([#include <zlib.h>], [int i = Z_OK;], 
      [AC_MSG_RESULT(found) 
       APR_ADDTO(MOD_DEFLATE_LDADD, [$ap_zlib_ldflags -lz])],
      [AC_MSG_RESULT(not found)
       enable_deflate=no
       if test "x$ap_zlib_with" = "x"; then
         AC_MSG_WARN([... Error, zlib was missing or unusable])
       else
         AC_MSG_ERROR([... Error, zlib was missing or unusable])
       fi
      ])
    INCLUDES=$ap_save_includes
    LDFLAGS=$ap_save_ldflags
    CPPFLAGS=$ap_save_cppflags
    APR_REMOVEFROM(LIBS, [-lz])
  fi
])

AC_DEFUN([FIND_LIBXML2], [
  AC_CACHE_CHECK([for libxml2], [ac_cv_libxml2], [
    AC_ARG_WITH(libxml2,
      [APACHE_HELP_STRING(--with-libxml2=PATH,location for libxml2)],
      [test_paths="${with_libxml2}"],
      [test_paths="/usr/include/libxml2 /usr/local/include/libxml2 /usr/include /usr/local/include"]
    )
    AC_MSG_CHECKING(for libxml2)
    xml2_path=""
    for x in ${test_paths}; do
        if test -f "${x}/libxml/parser.h"; then
          xml2_path="${x}"
          break
        fi
    done
    if test -n "${xml2_path}" ; then
      ac_cv_libxml2=yes
      XML2_INCLUDES="${xml2_path}"
    else
      ac_cv_libxml2=no
    fi
  ])
])

APACHE_MODULE(xml2enc, i18n support for markup filters, , , , [
  FIND_LIBXML2
  if test "$ac_cv_libxml2" = "yes" ; then
    APR_ADDTO(MOD_CFLAGS, [-I${XML2_INCLUDES}])
    APR_ADDTO(MOD_XML2ENC_LDADD, [-lxml2])
  else
    enable_xml2enc=no
  fi
])
APACHE_MODULE(proxy_html, Fix HTML Links in a Reverse Proxy, , , , [
  FIND_LIBXML2
  if test "$ac_cv_libxml2" = "yes" ; then
    APR_ADDTO(MOD_CFLAGS, [-I${XML2_INCLUDES}])
    APR_ADDTO(MOD_PROXY_HTML_LDADD, [-lxml2])
  else
    enable_proxy_html=no
  fi
]
)

dnl
dnl APACHE_CHECK_BROTLI
dnl
dnl Configure for Brotli, giving preference to
dnl "--with-brotli=<path>" if it was specified.
dnl
AC_DEFUN([APACHE_CHECK_BROTLI],[
  AC_CACHE_CHECK([for Brotli], [ac_cv_brotli], [
    dnl initialise the variables we use
    ac_cv_brotli=no
    ac_brotli_found=""
    ac_brotli_base=""
    ac_brotli_libs=""
    ac_brotli_mod_cflags=""
    ac_brotli_mod_ldflags=""

    dnl Determine the Brotli base directory, if any
    AC_MSG_CHECKING([for user-provided Brotli base directory])
    AC_ARG_WITH(brotli, APACHE_HELP_STRING(--with-brotli=PATH,Brotli installation directory), [
      dnl If --with-brotli specifies a directory, we use that directory
      if test "x$withval" != "xyes" -a "x$withval" != "x"; then
        dnl This ensures $withval is actually a directory and that it is absolute
        ac_brotli_base="`cd $withval ; pwd`"
      fi
    ])
    if test "x$ac_brotli_base" = "x"; then
      AC_MSG_RESULT(none)
    else
      AC_MSG_RESULT($ac_brotli_base)
    fi

    dnl Run header and version checks
    saved_CPPFLAGS="$CPPFLAGS"
    saved_LIBS="$LIBS"
    saved_LDFLAGS="$LDFLAGS"

    dnl Before doing anything else, load in pkg-config variables
    if test -n "$PKGCONFIG"; then
      saved_PKG_CONFIG_PATH="$PKG_CONFIG_PATH"
      if test "x$ac_brotli_base" != "x" -a \
              -f "${ac_brotli_base}/lib/pkgconfig/libbrotlienc.pc"; then
        dnl Ensure that the given path is used by pkg-config too, otherwise
        dnl the system libbrotlienc.pc might be picked up instead.
        PKG_CONFIG_PATH="${ac_brotli_base}/lib/pkgconfig${PKG_CONFIG_PATH+:}${PKG_CONFIG_PATH}"
        export PKG_CONFIG_PATH
      fi
      ac_brotli_libs="`$PKGCONFIG --libs-only-l --silence-errors libbrotlienc`"
      if test $? -eq 0; then
        ac_brotli_found="yes"
        pkglookup="`$PKGCONFIG --cflags-only-I libbrotlienc`"
        APR_ADDTO(CPPFLAGS, [$pkglookup])
        APR_ADDTO(MOD_CFLAGS, [$pkglookup])
        pkglookup="`$PKGCONFIG --libs-only-L libbrotlienc`"
        APR_ADDTO(LDFLAGS, [$pkglookup])
        APR_ADDTO(MOD_LDFLAGS, [$pkglookup])
        pkglookup="`$PKGCONFIG --libs-only-other libbrotlienc`"
        APR_ADDTO(LDFLAGS, [$pkglookup])
        APR_ADDTO(MOD_LDFLAGS, [$pkglookup])
      fi
      PKG_CONFIG_PATH="$saved_PKG_CONFIG_PATH"
    fi

    dnl fall back to the user-supplied directory if not found via pkg-config
    if test "x$ac_brotli_base" != "x" -a "x$ac_brotli_found" = "x"; then
      APR_ADDTO(CPPFLAGS, [-I$ac_brotli_base/include])
      APR_ADDTO(MOD_CFLAGS, [-I$ac_brotli_base/include])
      APR_ADDTO(LDFLAGS, [-L$ac_brotli_base/lib])
      APR_ADDTO(MOD_LDFLAGS, [-L$ac_brotli_base/lib])
      if test "x$ap_platform_runtime_link_flag" != "x"; then
        APR_ADDTO(LDFLAGS, [$ap_platform_runtime_link_flag$ac_brotli_base/lib])
        APR_ADDTO(MOD_LDFLAGS, [$ap_platform_runtime_link_flag$ac_brotli_base/lib])
      fi
    fi

    ac_brotli_libs="${ac_brotli_libs:--lbrotlienc `$apr_config --libs`} "
    APR_ADDTO(MOD_LDFLAGS, [$ac_brotli_libs])
    APR_ADDTO(LIBS, [$ac_brotli_libs])

    dnl Run library and function checks
    liberrors=""
    AC_CHECK_HEADERS([brotli/encode.h])
    AC_MSG_CHECKING([for Brotli version >= 0.6.0])
    AC_TRY_COMPILE([#include <brotli/encode.h>],[
const uint8_t *o = BrotliEncoderTakeOutput((BrotliEncoderState*)0, (size_t*)0);
if (o) return *o;],
      [AC_MSG_RESULT(OK)
       ac_cv_brotli="yes"],
      [AC_MSG_RESULT(FAILED)])

    dnl restore
    CPPFLAGS="$saved_CPPFLAGS"
    LIBS="$saved_LIBS"
    LDFLAGS="$saved_LDFLAGS"

    dnl cache MOD_LDFLAGS, MOD_CFLAGS
    ac_brotli_mod_cflags=$MOD_CFLAGS
    ac_brotli_mod_ldflags=$MOD_LDFLAGS
  ])
  if test "x$ac_cv_brotli" = "xyes"; then
    APR_ADDTO(MOD_LDFLAGS, [$ac_brotli_mod_ldflags])

    dnl Ouch!  libbrotlienc.1.so doesn't link against libm.so (-lm),
    dnl although it should.  Workaround that in our LDFLAGS:

    APR_ADDTO(MOD_LDFLAGS, ["-lm"])
    APR_ADDTO(MOD_CFLAGS, [$ac_brotli_mod_cflags])
  fi
])

APACHE_MODULE(brotli, Brotli compression support, , , most, [
  APACHE_CHECK_BROTLI
  if test "$ac_cv_brotli" = "yes" ; then
      if test "x$enable_brotli" = "xshared"; then
         # The only symbol which needs to be exported is the module
         # structure, so ask libtool to hide everything else:
         APR_ADDTO(MOD_BROTLI_LDADD, [-export-symbols-regex brotli_module])
      fi
  else
      enable_brotli=no
  fi
])

APR_ADDTO(INCLUDES, [-I\$(top_srcdir)/$modpath_current])

APACHE_MODPATH_FINISH
