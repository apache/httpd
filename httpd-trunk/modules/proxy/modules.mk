libmod_proxy.la: mod_proxy.lo proxy_util.lo
	$(MOD_LINK) mod_proxy.lo proxy_util.lo $(MOD_PROXY_LDADD)
libmod_proxy_connect.la: mod_proxy_connect.lo
	$(MOD_LINK) mod_proxy_connect.lo $(MOD_PROXY_CONNECT_LDADD)
libmod_proxy_ftp.la: mod_proxy_ftp.lo
	$(MOD_LINK) mod_proxy_ftp.lo $(MOD_PROXY_FTP_LDADD)
libmod_proxy_http.la: mod_proxy_http.lo
	$(MOD_LINK) mod_proxy_http.lo $(MOD_PROXY_HTTP_LDADD)
libmod_proxy_fcgi.la: mod_proxy_fcgi.lo
	$(MOD_LINK) mod_proxy_fcgi.lo $(MOD_PROXY_FCGI_LDADD)
libmod_proxy_scgi.la: mod_proxy_scgi.lo
	$(MOD_LINK) mod_proxy_scgi.lo $(MOD_PROXY_SCGI_LDADD)
libmod_proxy_ajp.la: mod_proxy_ajp.lo ajp_header.lo ajp_link.lo ajp_msg.lo ajp_utils.lo
	$(MOD_LINK) mod_proxy_ajp.lo ajp_header.lo ajp_link.lo ajp_msg.lo ajp_utils.lo $(MOD_PROXY_AJP_LDADD)
libmod_proxy_balancer.la: mod_proxy_balancer.lo
	$(MOD_LINK) mod_proxy_balancer.lo $(MOD_PROXY_BALANCER_LDADD)
libmod_proxy_express.la: mod_proxy_express.lo
	$(MOD_LINK) mod_proxy_express.lo $(MOD_PROXY_EXPRESS_LDADD)
DISTCLEAN_TARGETS = modules.mk
static =  libmod_proxy.la libmod_proxy_connect.la libmod_proxy_ftp.la libmod_proxy_http.la libmod_proxy_fcgi.la libmod_proxy_scgi.la libmod_proxy_ajp.la libmod_proxy_balancer.la libmod_proxy_express.la
shared = 
