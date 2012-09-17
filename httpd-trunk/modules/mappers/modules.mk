libmod_vhost_alias.la: mod_vhost_alias.lo
	$(MOD_LINK) mod_vhost_alias.lo $(MOD_VHOST_ALIAS_LDADD)
libmod_negotiation.la: mod_negotiation.lo
	$(MOD_LINK) mod_negotiation.lo $(MOD_NEGOTIATION_LDADD)
libmod_dir.la: mod_dir.lo
	$(MOD_LINK) mod_dir.lo $(MOD_DIR_LDADD)
libmod_actions.la: mod_actions.lo
	$(MOD_LINK) mod_actions.lo $(MOD_ACTIONS_LDADD)
libmod_speling.la: mod_speling.lo
	$(MOD_LINK) mod_speling.lo $(MOD_SPELING_LDADD)
libmod_userdir.la: mod_userdir.lo
	$(MOD_LINK) mod_userdir.lo $(MOD_USERDIR_LDADD)
libmod_alias.la: mod_alias.lo
	$(MOD_LINK) mod_alias.lo $(MOD_ALIAS_LDADD)
libmod_rewrite.la: mod_rewrite.lo
	$(MOD_LINK) mod_rewrite.lo $(MOD_REWRITE_LDADD)
DISTCLEAN_TARGETS = modules.mk
static =  libmod_vhost_alias.la libmod_negotiation.la libmod_dir.la libmod_actions.la libmod_speling.la libmod_userdir.la libmod_alias.la libmod_rewrite.la
shared = 
