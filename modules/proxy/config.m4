dnl modules enabled in this directory by default

APACHE_MODPATH_INIT(proxy)

proxy_objs="mod_proxy.lo proxy_util.lo"
APACHE_MODULE(proxy, Apache proxy module, $proxy_objs, , most)

dnl set aside module selections and default, and set the module default to the
dnl same scope (shared|static) as selected for mod proxy, along with setting
dnl the default selection to "most" for remaining proxy modules, mirroring the
dnl behavior of 2.4.1 and later, but failing ./configure only if an explicitly
dnl enabled module is missing its prereqs
save_module_selection=$module_selection
save_module_default=$module_default
if test "$enable_proxy" != "no"; then
    module_selection=most
    if test "$enable_proxy" = "shared" -o "$enable_proxy" = "static"; then
        module_default=$enable_proxy
    fi
fi

proxy_connect_objs="mod_proxy_connect.lo"
proxy_ftp_objs="mod_proxy_ftp.lo"
proxy_http_objs="mod_proxy_http.lo"
proxy_fcgi_objs="mod_proxy_fcgi.lo"
proxy_scgi_objs="mod_proxy_scgi.lo"
proxy_uwsgi_objs="mod_proxy_uwsgi.lo"
proxy_fdpass_objs="mod_proxy_fdpass.lo"
proxy_ajp_objs="mod_proxy_ajp.lo ajp_header.lo ajp_link.lo ajp_msg.lo ajp_utils.lo"
proxy_wstunnel_objs="mod_proxy_wstunnel.lo"
proxy_balancer_objs="mod_proxy_balancer.lo"

case "$host" in
  *os2*)
    # OS/2 DLLs must resolve all symbols at build time and
    # these sub-modules need some from the main proxy module
    proxy_connect_objs="$proxy_connect_objs mod_proxy.la"
    proxy_ftp_objs="$proxy_ftp_objs mod_proxy.la"
    proxy_http_objs="$proxy_http_objs mod_proxy.la"
    proxy_fcgi_objs="$proxy_fcgi_objs mod_proxy.la"
    proxy_scgi_objs="$proxy_scgi_objs mod_proxy.la"
    proxy_uwsgi_objs="$proxy_uwsgi_objs mod_proxy.la"
    proxy_fdpass_objs="$proxy_fdpass_objs mod_proxy.la"
    proxy_ajp_objs="$proxy_ajp_objs mod_proxy.la"
    proxy_wstunnel_objs="$proxy_wstunnel_objs mod_proxy.la"
    proxy_balancer_objs="$proxy_balancer_objs mod_proxy.la"
    ;;
esac

APACHE_MODULE(proxy_connect, Apache proxy CONNECT module.  Requires --enable-proxy., $proxy_connect_objs, , most, , proxy)
APACHE_MODULE(proxy_ftp, Apache proxy FTP module.  Requires --enable-proxy., $proxy_ftp_objs, , most, , proxy)
APACHE_MODULE(proxy_http, Apache proxy HTTP module.  Requires --enable-proxy., $proxy_http_objs, , most, , proxy)
APACHE_MODULE(proxy_fcgi, Apache proxy FastCGI module.  Requires --enable-proxy., $proxy_fcgi_objs, , most, , proxy)
APACHE_MODULE(proxy_scgi, Apache proxy SCGI module.  Requires --enable-proxy., $proxy_scgi_objs, , most, , proxy)
APACHE_MODULE(proxy_uwsgi, Apache proxy UWSGI module.  Requires --enable-proxy., $proxy_uwsgi_objs, , most, , proxy)
APACHE_MODULE(proxy_fdpass, Apache proxy to Unix Daemon Socket module.  Requires --enable-proxy., $proxy_fdpass_objs, , most, [
  AC_CHECK_DECL(CMSG_DATA,,, [
    #include <sys/types.h>
    #include <sys/socket.h>
  ])
  if test $ac_cv_have_decl_CMSG_DATA = "no"; then
    AC_MSG_WARN([Your system does not support CMSG_DATA.])
    enable_proxy_fdpass=no
  fi
],proxy)
APACHE_MODULE(proxy_wstunnel, Apache proxy Websocket Tunnel module.  Requires --enable-proxy., $proxy_wstunnel_objs, , most, , proxy)
APACHE_MODULE(proxy_ajp, Apache proxy AJP module.  Requires --enable-proxy., $proxy_ajp_objs, , most, , proxy)
APACHE_MODULE(proxy_balancer, Apache proxy BALANCER module.  Requires --enable-proxy., $proxy_balancer_objs, , most, , proxy)

APACHE_MODULE(proxy_express, mass reverse-proxy module. Requires --enable-proxy., , , most, , proxy)
APACHE_MODULE(proxy_hcheck, [reverse-proxy health-check module. Requires --enable-proxy and --enable-watchdog.], , , most, , [proxy,watchdog])

APR_ADDTO(INCLUDES, [-I\$(top_srcdir)/$modpath_current -I\$(top_srcdir)/modules/http2])

module_selection=$save_module_selection
module_default=$save_module_default

APACHE_MODPATH_FINISH

