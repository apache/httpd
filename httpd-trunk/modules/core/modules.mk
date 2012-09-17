libmod_so.la: mod_so.lo
	$(MOD_LINK) mod_so.lo $(MOD_SO_LDADD)
DISTCLEAN_TARGETS = modules.mk
static =  libmod_so.la
shared = 
