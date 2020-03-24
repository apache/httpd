mod_dav.la: mod_dav.slo props.slo util.slo util_lock.slo liveprop.slo providers.slo std_liveprop.slo
	$(SH_LINK) -rpath $(libexecdir) -module -avoid-version  mod_dav.lo props.lo util.lo util_lock.lo liveprop.lo providers.lo std_liveprop.lo $(MOD_DAV_LDADD)
DISTCLEAN_TARGETS = modules.mk
static = 
shared =  mod_dav.la
