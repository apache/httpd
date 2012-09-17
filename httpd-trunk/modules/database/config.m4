
APACHE_MODPATH_INIT(database)

APACHE_MODULE(dbd, Apache DBD Framework, , , most)

APR_ADDTO(INCLUDES, [-I\$(top_srcdir)/$modpath_current])

APACHE_MODPATH_FINISH
