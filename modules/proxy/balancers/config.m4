APACHE_MODPATH_INIT(proxy/balancers)
if test "$enable_proxy" = "shared"; then
  proxy_mods_enable=shared
elif test "$enable_proxy" = "yes"; then
  proxy_mods_enable=yes
else
  proxy_mods_enable=no
fi

proxy_lb_hb_objs="mod_lbmethod_heartbeat.lo"
APACHE_MODULE(lbmethod_heartbeat, Apache proxy Load balancing from Heartbeats, $proxy_lb_hb_objs, , $proxy_mods_enable)

APACHE_MODPATH_FINISH
