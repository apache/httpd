dnl modules enabled in this directory by default
APACHE_MODPATH_INIT(standard)

dnl APACHE_MODULE(vhost_alias,blabla)
	
APACHE_MODULE(log_config, logging configuration, , config_log, yes)

APACHE_MODPATH_FINISH
    
APACHE_SUBST(STANDARD_LIBS)
