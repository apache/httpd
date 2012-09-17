libmod_apreq.la: filter.lo handle.lo
	$(MOD_LINK) filter.lo handle.lo $(MOD_APREQ_LDADD)
DISTCLEAN_TARGETS = modules.mk
static =  libmod_apreq.la
shared = 
