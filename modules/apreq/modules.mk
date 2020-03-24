mod_apreq.la: filter.slo handle.slo
	$(SH_LINK) -rpath $(libexecdir) -module -avoid-version  filter.lo handle.lo $(MOD_APREQ_LDADD)
DISTCLEAN_TARGETS = modules.mk
static = 
shared =  mod_apreq.la
