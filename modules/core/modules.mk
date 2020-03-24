libmod_so.la: mod_so.lo
	$(MOD_LINK) mod_so.lo $(MOD_SO_LDADD)
mod_watchdog.la: mod_watchdog.slo
	$(SH_LINK) -rpath $(libexecdir) -module -avoid-version  mod_watchdog.lo $(MOD_WATCHDOG_LDADD)
mod_macro.la: mod_macro.slo
	$(SH_LINK) -rpath $(libexecdir) -module -avoid-version  mod_macro.lo $(MOD_MACRO_LDADD)
DISTCLEAN_TARGETS = modules.mk
static =  libmod_so.la
shared =  mod_watchdog.la mod_macro.la
