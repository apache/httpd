dnl modules enabled in this directory by default

APACHE_MODPATH_INIT(proxy)

if test "$enable_proxy" = "no"; then
  proxy_mods_enable=no
else
  proxy_mods_enable=yes
fi
APACHE_MODULE(dav_fs, DAV provider for the filesystem, $dav_fs_objects, ,$dav_fs_enable)

proxy_objs="mod_proxy.lo proxy_util.lo"
APACHE_MODULE(proxy, Apache proxy module, $proxy_objs, , no)

proxy_connect_objs="proxy_connect.lo proxy_util.lo"
APACHE_MODULE(proxy_connect, Apache proxy CONNECT module, $proxy_connect_objs, , $proxy_mods_enable)
proxy_ftp_objs="proxy_ftp.lo proxy_util.lo"
APACHE_MODULE(proxy_ftp, Apache proxy FTP module, $proxy_ftp_objs, , $proxy_mods_enable)
proxy_http_objs="proxy_http.lo proxy_util.lo"
APACHE_MODULE(proxy_http, Apache proxy HTTP module, $proxy_http_objs, , $proxy_mods_enable)


APACHE_MODPATH_FINISH
