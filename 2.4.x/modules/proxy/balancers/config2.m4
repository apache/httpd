APACHE_MODPATH_INIT(proxy/balancers)

APACHE_MODULE(lbmethod_byrequests, Apache proxy Load balancing by request counting, , , $enable_proxy_balancer, , proxy_balancer)
APACHE_MODULE(lbmethod_bytraffic, Apache proxy Load balancing by traffic counting, , , $enable_proxy_balancer, , proxy_balancer)
APACHE_MODULE(lbmethod_bybusyness, Apache proxy Load balancing by busyness, , , $enable_proxy_balancer, , proxy_balancer)
APACHE_MODULE(lbmethod_heartbeat, Apache proxy Load balancing from Heartbeats, , , $enable_proxy_balancer, , proxy_balancer)

APACHE_MODPATH_FINISH
