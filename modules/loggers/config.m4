dnl modules enabled in this directory by default

dnl APACHE_MODULE(name, helptext[, objects[, structname[, default[, config]]]])

APACHE_MODPATH_INIT(loggers)
	
APACHE_MODULE(log_config, logging configuration, , , yes)
APACHE_MODULE(log_forensic, forensic logging)

if test "x$enable_log_forensic" != "xno"; then
    # mod_log_forensic needs test_char.h
    APR_ADDTO(INCLUDES, [-I\$(top_builddir)/server])
fi   

APACHE_MODULE(logio, input and output logging, , , most)

APR_ADDTO(INCLUDES, [-I\$(top_srcdir)/$modpath_current])

APACHE_MODPATH_FINISH
