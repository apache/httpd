libmod_authn_file.la: mod_authn_file.lo
	$(MOD_LINK) mod_authn_file.lo $(MOD_AUTHN_FILE_LDADD)
libmod_authn_dbm.la: mod_authn_dbm.lo
	$(MOD_LINK) mod_authn_dbm.lo $(MOD_AUTHN_DBM_LDADD)
libmod_authn_anon.la: mod_authn_anon.lo
	$(MOD_LINK) mod_authn_anon.lo $(MOD_AUTHN_ANON_LDADD)
libmod_authn_dbd.la: mod_authn_dbd.lo
	$(MOD_LINK) mod_authn_dbd.lo $(MOD_AUTHN_DBD_LDADD)
libmod_authn_socache.la: mod_authn_socache.lo
	$(MOD_LINK) mod_authn_socache.lo $(MOD_AUTHN_SOCACHE_LDADD)
libmod_authn_core.la: mod_authn_core.lo
	$(MOD_LINK) mod_authn_core.lo $(MOD_AUTHN_CORE_LDADD)
libmod_authz_host.la: mod_authz_host.lo
	$(MOD_LINK) mod_authz_host.lo $(MOD_AUTHZ_HOST_LDADD)
libmod_authz_groupfile.la: mod_authz_groupfile.lo
	$(MOD_LINK) mod_authz_groupfile.lo $(MOD_AUTHZ_GROUPFILE_LDADD)
libmod_authz_user.la: mod_authz_user.lo
	$(MOD_LINK) mod_authz_user.lo $(MOD_AUTHZ_USER_LDADD)
libmod_authz_dbm.la: mod_authz_dbm.lo
	$(MOD_LINK) mod_authz_dbm.lo $(MOD_AUTHZ_DBM_LDADD)
libmod_authz_owner.la: mod_authz_owner.lo
	$(MOD_LINK) mod_authz_owner.lo $(MOD_AUTHZ_OWNER_LDADD)
libmod_authz_dbd.la: mod_authz_dbd.lo
	$(MOD_LINK) mod_authz_dbd.lo $(MOD_AUTHZ_DBD_LDADD)
libmod_authz_core.la: mod_authz_core.lo
	$(MOD_LINK) mod_authz_core.lo $(MOD_AUTHZ_CORE_LDADD)
libmod_access_compat.la: mod_access_compat.lo
	$(MOD_LINK) mod_access_compat.lo $(MOD_ACCESS_COMPAT_LDADD)
libmod_auth_basic.la: mod_auth_basic.lo
	$(MOD_LINK) mod_auth_basic.lo $(MOD_AUTH_BASIC_LDADD)
libmod_auth_form.la: mod_auth_form.lo
	$(MOD_LINK) mod_auth_form.lo $(MOD_AUTH_FORM_LDADD)
libmod_auth_digest.la: mod_auth_digest.lo
	$(MOD_LINK) mod_auth_digest.lo $(MOD_AUTH_DIGEST_LDADD)
libmod_allowmethods.la: mod_allowmethods.lo
	$(MOD_LINK) mod_allowmethods.lo $(MOD_ALLOWMETHODS_LDADD)
DISTCLEAN_TARGETS = modules.mk
static =  libmod_authn_file.la libmod_authn_dbm.la libmod_authn_anon.la libmod_authn_dbd.la libmod_authn_socache.la libmod_authn_core.la libmod_authz_host.la libmod_authz_groupfile.la libmod_authz_user.la libmod_authz_dbm.la libmod_authz_owner.la libmod_authz_dbd.la libmod_authz_core.la libmod_access_compat.la libmod_auth_basic.la libmod_auth_form.la libmod_auth_digest.la libmod_allowmethods.la
shared = 
