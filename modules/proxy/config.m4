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

proxy_connect_objs="proxy_connect.lo"
proxy_ftp_objs="proxy_ftp.lo"
proxy_http_objs="proxy_http.lo"

case "$host" in
  *os2*)
    # OS/2 DLLs must resolve all symbols at build time and
    # these sub-modules need some from the main proxy module
    proxy_connect_objs="$proxy_connect_objs mod_proxy.la"
    proxy_ftp_objs="$proxy_ftp_objs mod_proxy.la"
    proxy_http_objs="$proxy_http_objs mod_proxy.la"
    ;;
esac

APACHE_MODULE(proxy_connect, Apache proxy CONNECT module, $proxy_connect_objs, , $proxy_mods_enable)
APACHE_MODULE(proxy_ftp, Apache proxy FTP module, $proxy_ftp_objs, , $proxy_mods_enable)
APACHE_MODULE(proxy_http, Apache proxy HTTP module, $proxy_http_objs, , $proxy_mods_enable)

APACHE_MODPATH_FINISH
