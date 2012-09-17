APACHE_MODPATH_INIT(proxy/balancers)

APACHE_MODULE(lbmethod_byrequests, Apache proxy Load balancing by request counting, , , $proxy_mods_enable)
APACHE_MODULE(lbmethod_bytraffic, Apache proxy Load balancing by traffic counting, , , $proxy_mods_enable)
APACHE_MODULE(lbmethod_bybusyness, Apache proxy Load balancing by busyness, , , $proxy_mods_enable)
APACHE_MODULE(lbmethod_heartbeat, Apache proxy Load balancing from Heartbeats, , , $proxy_mods_enable)

APACHE_MODPATH_FINISH
