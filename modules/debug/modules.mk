libmod_dumpio.la: mod_dumpio.lo
	$(MOD_LINK) mod_dumpio.lo $(MOD_DUMPIO_LDADD)
DISTCLEAN_TARGETS = modules.mk
static =  libmod_dumpio.la
shared = 
