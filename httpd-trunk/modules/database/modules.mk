libmod_dbd.la: mod_dbd.lo
	$(MOD_LINK) mod_dbd.lo $(MOD_DBD_LDADD)
DISTCLEAN_TARGETS = modules.mk
static =  libmod_dbd.la
shared = 
