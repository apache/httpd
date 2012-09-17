libmod_dav.la: mod_dav.lo props.lo util.lo util_lock.lo liveprop.lo providers.lo std_liveprop.lo
	$(MOD_LINK) mod_dav.lo props.lo util.lo util_lock.lo liveprop.lo providers.lo std_liveprop.lo $(MOD_DAV_LDADD)
DISTCLEAN_TARGETS = modules.mk
static =  libmod_dav.la
shared = 
