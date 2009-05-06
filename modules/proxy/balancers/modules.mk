libmod_lbmethod_byrequests.la: mod_lbmethod_byrequests.lo
	$(MOD_LINK) mod_lbmethod_byrequests.lo $(MOD_LBMETHOD_BYREQUESTS_LDADD)
libmod_lbmethod_bytraffic.la: mod_lbmethod_bytraffic.lo
	$(MOD_LINK) mod_lbmethod_bytraffic.lo $(MOD_LBMETHOD_BYTRAFFIC_LDADD)
libmod_lbmethod_bybusyness.la: mod_lbmethod_bybusyness.lo
	$(MOD_LINK) mod_lbmethod_bybusyness.lo $(MOD_LBMETHOD_BYBUSYNESS_LDADD)
libmod_lbmethod_heartbeat.la: mod_lbmethod_heartbeat.lo
	$(MOD_LINK) mod_lbmethod_heartbeat.lo $(MOD_LBMETHOD_HEARTBEAT_LDADD)
DISTCLEAN_TARGETS = modules.mk
static =  libmod_lbmethod_byrequests.la libmod_lbmethod_bytraffic.la libmod_lbmethod_bybusyness.la libmod_lbmethod_heartbeat.la
shared = 
