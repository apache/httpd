
APACHE_MODPATH_INIT(test)

APACHE_MODULE(optional_hook_export, example optional hook exporter, , , no)
APACHE_MODULE(optional_hook_import, example optional hook importer, , , no)
APACHE_MODULE(optional_fn_import, example optional function importer, , , no)
APACHE_MODULE(optional_fn_export, example optional function exporter, , , no)

APACHE_MODULE(dialup, rate limits static files to dialup modem speeds, , , )

APR_ADDTO(INCLUDES, [-I\$(top_srcdir)/$modpath_current])

APACHE_MODPATH_FINISH
