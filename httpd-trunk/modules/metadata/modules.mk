libmod_env.la: mod_env.lo
	$(MOD_LINK) mod_env.lo $(MOD_ENV_LDADD)
libmod_expires.la: mod_expires.lo
	$(MOD_LINK) mod_expires.lo $(MOD_EXPIRES_LDADD)
libmod_headers.la: mod_headers.lo
	$(MOD_LINK) mod_headers.lo $(MOD_HEADERS_LDADD)
libmod_unique_id.la: mod_unique_id.lo
	$(MOD_LINK) mod_unique_id.lo $(MOD_UNIQUE_ID_LDADD)
libmod_setenvif.la: mod_setenvif.lo
	$(MOD_LINK) mod_setenvif.lo $(MOD_SETENVIF_LDADD)
libmod_version.la: mod_version.lo
	$(MOD_LINK) mod_version.lo $(MOD_VERSION_LDADD)
libmod_remoteip.la: mod_remoteip.lo
	$(MOD_LINK) mod_remoteip.lo $(MOD_REMOTEIP_LDADD)
DISTCLEAN_TARGETS = modules.mk
static =  libmod_env.la libmod_expires.la libmod_headers.la libmod_unique_id.la libmod_setenvif.la libmod_version.la libmod_remoteip.la
shared = 
