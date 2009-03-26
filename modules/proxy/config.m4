dnl modules enabled in this directory by default

APACHE_MODPATH_INIT(proxy)

if test "$enable_proxy" = "shared"; then
  proxy_mods_enable=shared
elif test "$enable_proxy" = "yes"; then
  proxy_mods_enable=yes
else
  proxy_mods_enable=no
fi

proxy_objs="mod_proxy.lo proxy_util.lo"
APACHE_MODULE(proxy, Apache proxy module, $proxy_objs, , $proxy_mods_enable)

proxy_connect_objs="mod_proxy_connect.lo"
proxy_ftp_objs="mod_proxy_ftp.lo"
proxy_http_objs="mod_proxy_http.lo"
proxy_fcgi_objs="mod_proxy_fcgi.lo"
proxy_scgi_objs="mod_proxy_scgi.lo"
proxy_fdpass_objs="mod_proxy_fdpass.lo"
proxy_ajp_objs="mod_proxy_ajp.lo ajp_header.lo ajp_link.lo ajp_msg.lo ajp_utils.lo"
proxy_balancer_objs="mod_proxy_balancer.lo"

APACHE_MODULE(proxy_connect, Apache proxy CONNECT module, $proxy_connect_objs, , $proxy_mods_enable)
APACHE_MODULE(proxy_ftp, Apache proxy FTP module, $proxy_ftp_objs, , $proxy_mods_enable)
APACHE_MODULE(proxy_http, Apache proxy HTTP module, $proxy_http_objs, , $proxy_mods_enable)
APACHE_MODULE(proxy_fcgi, Apache proxy FastCGI module, $proxy_fcgi_objs, , $proxy_mods_enable)
APACHE_MODULE(proxy_scgi, Apache proxy SCGI module, $proxy_scgi_objs, , $proxy_mods_enable)
APACHE_MODULE(proxy_fdpass, Apache proxy to Unix Daemon Socket module, $proxy_fdpass_objs, , $proxy_mods_enable, [
  AC_CHECK_DECLS(CMSG_DATA, [ap_HAVE_DECL_CMSG_DATA="yes"], [ap_HAVE_DECL_CMSG_DATA="no"], [[#include <sys/socket.h>]])
  if test $ap_HAVE_DECL_CMSG_DATA = "no"; then
    AC_MSG_WARN([Your system does not support CMSG_DATA.])
    enable_proxy_fdpass="no"
    _apmod_error_fatal="no"
  fi
])
APACHE_MODULE(proxy_ajp, Apache proxy AJP module, $proxy_ajp_objs, , $proxy_mods_enable)
APACHE_MODULE(proxy_balancer, Apache proxy BALANCER module, $proxy_balancer_objs, , $proxy_mods_enable)


AC_DEFUN([CHECK_SERF], [
  serf_found="no"
  AC_ARG_WITH(serf, APACHE_HELP_STRING([--with-serf=PREFIX],
                                  [Serf client library]),
  [
    if test "$withval" = "yes" ; then
      AC_MSG_ERROR([--with-serf requires an argument.])
    else
      serf_prefix=$withval
      save_cppflags="$CPPFLAGS"
      CPPFLAGS="$CPPFLAGS $APR_INCLUDES $APU_INCLUDES -I$serf_prefix/include/serf-0"
      AC_CHECK_HEADERS(serf.h,[
        save_ldflags="$LDFLAGS"
        LDFLAGS="$LDFLAGS -L$serf_prefix/lib"
        AC_CHECK_LIB(serf-0, serf_context_create,[serf_found="yes"])
        LDFLAGS="$save_ldflags"])
      CPPFLAGS="$save_cppflags"
    fi
  ])

  if test "$serf_found" = "yes"; then
    MOD_SERF_LDADD="-L$serf_prefix/lib -lserf-0"
    APR_ADDTO(INCLUDES, ["-I$serf_prefix/include/serf-0"])
  else
    AC_MSG_ERROR(unable to find serf)
  fi
])

APACHE_MODULE(serf, [Reverse proxy module using Serf], , , no, [
    CHECK_SERF
])

APR_ADDTO(INCLUDES, [-I\$(top_srcdir)/$modpath_current/../generators])
APACHE_MODPATH_FINISH

