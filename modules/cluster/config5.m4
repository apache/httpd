
APACHE_MODPATH_INIT(cluster)

APACHE_MODULE(heartbeat, Generates Heartbeats, , , most)
APACHE_MODULE(heartmonitor, Collects Heartbeats, , , most)

APACHE_MODPATH_FINISH
