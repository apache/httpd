mod_authn_file.la: mod_authn_file.slo
	$(SH_LINK) -rpath $(libexecdir) -module -avoid-version  mod_authn_file.lo $(MOD_AUTHN_FILE_LDADD)
mod_authn_dbm.la: mod_authn_dbm.slo
	$(SH_LINK) -rpath $(libexecdir) -module -avoid-version  mod_authn_dbm.lo $(MOD_AUTHN_DBM_LDADD)
mod_authn_anon.la: mod_authn_anon.slo
	$(SH_LINK) -rpath $(libexecdir) -module -avoid-version  mod_authn_anon.lo $(MOD_AUTHN_ANON_LDADD)
mod_authn_dbd.la: mod_authn_dbd.slo
	$(SH_LINK) -rpath $(libexecdir) -module -avoid-version  mod_authn_dbd.lo $(MOD_AUTHN_DBD_LDADD)
mod_authn_socache.la: mod_authn_socache.slo
	$(SH_LINK) -rpath $(libexecdir) -module -avoid-version  mod_authn_socache.lo $(MOD_AUTHN_SOCACHE_LDADD)
mod_authn_core.la: mod_authn_core.slo
	$(SH_LINK) -rpath $(libexecdir) -module -avoid-version  mod_authn_core.lo $(MOD_AUTHN_CORE_LDADD)
mod_authz_host.la: mod_authz_host.slo
	$(SH_LINK) -rpath $(libexecdir) -module -avoid-version  mod_authz_host.lo $(MOD_AUTHZ_HOST_LDADD)
mod_authz_groupfile.la: mod_authz_groupfile.slo
	$(SH_LINK) -rpath $(libexecdir) -module -avoid-version  mod_authz_groupfile.lo $(MOD_AUTHZ_GROUPFILE_LDADD)
mod_authz_user.la: mod_authz_user.slo
	$(SH_LINK) -rpath $(libexecdir) -module -avoid-version  mod_authz_user.lo $(MOD_AUTHZ_USER_LDADD)
mod_authz_dbm.la: mod_authz_dbm.slo
	$(SH_LINK) -rpath $(libexecdir) -module -avoid-version  mod_authz_dbm.lo $(MOD_AUTHZ_DBM_LDADD)
mod_authz_owner.la: mod_authz_owner.slo
	$(SH_LINK) -rpath $(libexecdir) -module -avoid-version  mod_authz_owner.lo $(MOD_AUTHZ_OWNER_LDADD)
mod_authz_dbd.la: mod_authz_dbd.slo
	$(SH_LINK) -rpath $(libexecdir) -module -avoid-version  mod_authz_dbd.lo $(MOD_AUTHZ_DBD_LDADD)
mod_authz_core.la: mod_authz_core.slo
	$(SH_LINK) -rpath $(libexecdir) -module -avoid-version  mod_authz_core.lo $(MOD_AUTHZ_CORE_LDADD)
mod_access_compat.la: mod_access_compat.slo
	$(SH_LINK) -rpath $(libexecdir) -module -avoid-version  mod_access_compat.lo $(MOD_ACCESS_COMPAT_LDADD)
mod_auth_basic.la: mod_auth_basic.slo
	$(SH_LINK) -rpath $(libexecdir) -module -avoid-version  mod_auth_basic.lo $(MOD_AUTH_BASIC_LDADD)
mod_auth_form.la: mod_auth_form.slo
	$(SH_LINK) -rpath $(libexecdir) -module -avoid-version  mod_auth_form.lo $(MOD_AUTH_FORM_LDADD)
mod_auth_digest.la: mod_auth_digest.slo
	$(SH_LINK) -rpath $(libexecdir) -module -avoid-version  mod_auth_digest.lo $(MOD_AUTH_DIGEST_LDADD)
mod_allowmethods.la: mod_allowmethods.slo
	$(SH_LINK) -rpath $(libexecdir) -module -avoid-version  mod_allowmethods.lo $(MOD_ALLOWMETHODS_LDADD)
mod_allowhandlers.la: mod_allowhandlers.slo
	$(SH_LINK) -rpath $(libexecdir) -module -avoid-version  mod_allowhandlers.lo $(MOD_ALLOWHANDLERS_LDADD)
DISTCLEAN_TARGETS = modules.mk
static = 
shared =  mod_authn_file.la mod_authn_dbm.la mod_authn_anon.la mod_authn_dbd.la mod_authn_socache.la mod_authn_core.la mod_authz_host.la mod_authz_groupfile.la mod_authz_user.la mod_authz_dbm.la mod_authz_owner.la mod_authz_dbd.la mod_authz_core.la mod_access_compat.la mod_auth_basic.la mod_auth_form.la mod_auth_digest.la mod_allowmethods.la mod_allowhandlers.la
