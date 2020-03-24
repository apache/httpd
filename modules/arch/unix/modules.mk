mod_unixd.la: mod_unixd.slo
	$(SH_LINK) -rpath $(libexecdir) -module -avoid-version  mod_unixd.lo $(MOD_UNIXD_LDADD)
DISTCLEAN_TARGETS = modules.mk
static = 
shared =  mod_unixd.la
