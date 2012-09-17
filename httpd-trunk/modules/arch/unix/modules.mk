libmod_unixd.la: mod_unixd.lo
	$(MOD_LINK) mod_unixd.lo $(MOD_UNIXD_LDADD)
DISTCLEAN_TARGETS = modules.mk
static =  libmod_unixd.la
shared = 
