mod_log_config.la: mod_log_config.slo
	$(SH_LINK) -rpath $(libexecdir) -module -avoid-version  mod_log_config.lo $(MOD_LOG_CONFIG_LDADD)
mod_log_debug.la: mod_log_debug.slo
	$(SH_LINK) -rpath $(libexecdir) -module -avoid-version  mod_log_debug.lo $(MOD_LOG_DEBUG_LDADD)
mod_logio.la: mod_logio.slo
	$(SH_LINK) -rpath $(libexecdir) -module -avoid-version  mod_logio.lo $(MOD_LOGIO_LDADD)
DISTCLEAN_TARGETS = modules.mk
static = 
shared =  mod_log_config.la mod_log_debug.la mod_logio.la
