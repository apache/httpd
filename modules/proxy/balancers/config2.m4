APACHE_MODPATH_INIT(proxy/balancers)
if test "$enable_proxy" = "shared"; then
  proxy_mods_enable=shared
elif test "$enable_proxy" = "yes"; then
  proxy_mods_enable=yes
else
  proxy_mods_enable=no
fi

proxy_lb_br_objs="mod_lbmethod_byrequests.lo"
proxy_lb_bt_objs="mod_lbmethod_bytraffic.lo"
proxy_lb_bb_objs="mod_lbmethod_bybusyness.lo"
proxy_lb_hb_objs="mod_lbmethod_heartbeat.lo"

APACHE_MODULE(lbmethod_byrequests, Apache proxy Load balancing by request counting, $proxy_lb_br_objs, , $proxy_mods_enable)
APACHE_MODULE(lbmethod_bytraffic, Apache proxy Load balancing by traffic counting, $proxy_lb_bt_objs, , $proxy_mods_enable)
APACHE_MODULE(lbmethod_bybusyness, Apache proxy Load balancing by busyness, $proxy_lb_bb_objs, , $proxy_mods_enable)
APACHE_MODULE(lbmethod_heartbeat, Apache proxy Load balancing from Heartbeats, $proxy_lb_hb_objs, , $proxy_mods_enable)

APACHE_MODPATH_FINISH
