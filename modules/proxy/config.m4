dnl modules enabled in this directory by default

APACHE_MODPATH_INIT(proxy)

proxy_objs="mod_proxy.lo proxy_connect.lo proxy_http.lo proxy_util.lo"

APACHE_MODULE(proxy, Apache proxy module, $proxy_objs, , no)

APACHE_MODPATH_FINISH
