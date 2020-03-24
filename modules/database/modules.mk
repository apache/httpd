mod_dbd.la: mod_dbd.slo
	$(SH_LINK) -rpath $(libexecdir) -module -avoid-version  mod_dbd.lo $(MOD_DBD_LDADD)
DISTCLEAN_TARGETS = modules.mk
static = 
shared =  mod_dbd.la
