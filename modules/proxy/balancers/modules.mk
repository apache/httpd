mod_lbmethod_byrequests.la: mod_lbmethod_byrequests.slo
	$(SH_LINK) -rpath $(libexecdir) -module -avoid-version  mod_lbmethod_byrequests.lo $(MOD_LBMETHOD_BYREQUESTS_LDADD)
mod_lbmethod_bytraffic.la: mod_lbmethod_bytraffic.slo
	$(SH_LINK) -rpath $(libexecdir) -module -avoid-version  mod_lbmethod_bytraffic.lo $(MOD_LBMETHOD_BYTRAFFIC_LDADD)
mod_lbmethod_bybusyness.la: mod_lbmethod_bybusyness.slo
	$(SH_LINK) -rpath $(libexecdir) -module -avoid-version  mod_lbmethod_bybusyness.lo $(MOD_LBMETHOD_BYBUSYNESS_LDADD)
mod_lbmethod_heartbeat.la: mod_lbmethod_heartbeat.slo
	$(SH_LINK) -rpath $(libexecdir) -module -avoid-version  mod_lbmethod_heartbeat.lo $(MOD_LBMETHOD_HEARTBEAT_LDADD)
DISTCLEAN_TARGETS = modules.mk
static = 
shared =  mod_lbmethod_byrequests.la mod_lbmethod_bytraffic.la mod_lbmethod_bybusyness.la mod_lbmethod_heartbeat.la
