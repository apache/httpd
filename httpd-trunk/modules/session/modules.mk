libmod_session.la: mod_session.lo
	$(MOD_LINK) mod_session.lo $(MOD_SESSION_LDADD)
libmod_session_cookie.la: mod_session_cookie.lo
	$(MOD_LINK) mod_session_cookie.lo $(MOD_SESSION_COOKIE_LDADD)
libmod_session_dbd.la: mod_session_dbd.lo
	$(MOD_LINK) mod_session_dbd.lo $(MOD_SESSION_DBD_LDADD)
DISTCLEAN_TARGETS = modules.mk
static =  libmod_session.la libmod_session_cookie.la libmod_session_dbd.la
shared = 
