libmod_log_config.la: mod_log_config.lo
	$(MOD_LINK) mod_log_config.lo $(MOD_LOG_CONFIG_LDADD)
libmod_log_debug.la: mod_log_debug.lo
	$(MOD_LINK) mod_log_debug.lo $(MOD_LOG_DEBUG_LDADD)
libmod_logio.la: mod_logio.lo
	$(MOD_LINK) mod_logio.lo $(MOD_LOGIO_LDADD)
DISTCLEAN_TARGETS = modules.mk
static =  libmod_log_config.la libmod_log_debug.la libmod_logio.la
shared = 
