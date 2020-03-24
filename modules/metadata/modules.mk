mod_env.la: mod_env.slo
	$(SH_LINK) -rpath $(libexecdir) -module -avoid-version  mod_env.lo $(MOD_ENV_LDADD)
mod_expires.la: mod_expires.slo
	$(SH_LINK) -rpath $(libexecdir) -module -avoid-version  mod_expires.lo $(MOD_EXPIRES_LDADD)
mod_headers.la: mod_headers.slo
	$(SH_LINK) -rpath $(libexecdir) -module -avoid-version  mod_headers.lo $(MOD_HEADERS_LDADD)
mod_unique_id.la: mod_unique_id.slo
	$(SH_LINK) -rpath $(libexecdir) -module -avoid-version  mod_unique_id.lo $(MOD_UNIQUE_ID_LDADD)
mod_setenvif.la: mod_setenvif.slo
	$(SH_LINK) -rpath $(libexecdir) -module -avoid-version  mod_setenvif.lo $(MOD_SETENVIF_LDADD)
mod_version.la: mod_version.slo
	$(SH_LINK) -rpath $(libexecdir) -module -avoid-version  mod_version.lo $(MOD_VERSION_LDADD)
mod_remoteip.la: mod_remoteip.slo
	$(SH_LINK) -rpath $(libexecdir) -module -avoid-version  mod_remoteip.lo $(MOD_REMOTEIP_LDADD)
DISTCLEAN_TARGETS = modules.mk
static = 
shared =  mod_env.la mod_expires.la mod_headers.la mod_unique_id.la mod_setenvif.la mod_version.la mod_remoteip.la
