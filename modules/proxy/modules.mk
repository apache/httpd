mod_proxy.la: mod_proxy.slo proxy_util.slo
	$(SH_LINK) -rpath $(libexecdir) -module -avoid-version  mod_proxy.lo proxy_util.lo $(MOD_PROXY_LDADD)
mod_proxy_connect.la: mod_proxy_connect.slo
	$(SH_LINK) -rpath $(libexecdir) -module -avoid-version  mod_proxy_connect.lo $(MOD_PROXY_CONNECT_LDADD)
mod_proxy_ftp.la: mod_proxy_ftp.slo
	$(SH_LINK) -rpath $(libexecdir) -module -avoid-version  mod_proxy_ftp.lo $(MOD_PROXY_FTP_LDADD)
mod_proxy_http.la: mod_proxy_http.slo
	$(SH_LINK) -rpath $(libexecdir) -module -avoid-version  mod_proxy_http.lo $(MOD_PROXY_HTTP_LDADD)
mod_proxy_fcgi.la: mod_proxy_fcgi.slo
	$(SH_LINK) -rpath $(libexecdir) -module -avoid-version  mod_proxy_fcgi.lo $(MOD_PROXY_FCGI_LDADD)
mod_proxy_scgi.la: mod_proxy_scgi.slo
	$(SH_LINK) -rpath $(libexecdir) -module -avoid-version  mod_proxy_scgi.lo $(MOD_PROXY_SCGI_LDADD)
mod_proxy_uwsgi.la: mod_proxy_uwsgi.slo
	$(SH_LINK) -rpath $(libexecdir) -module -avoid-version  mod_proxy_uwsgi.lo $(MOD_PROXY_UWSGI_LDADD)
mod_proxy_fdpass.la: mod_proxy_fdpass.slo
	$(SH_LINK) -rpath $(libexecdir) -module -avoid-version  mod_proxy_fdpass.lo $(MOD_PROXY_FDPASS_LDADD)
mod_proxy_wstunnel.la: mod_proxy_wstunnel.slo
	$(SH_LINK) -rpath $(libexecdir) -module -avoid-version  mod_proxy_wstunnel.lo $(MOD_PROXY_WSTUNNEL_LDADD)
mod_proxy_ajp.la: mod_proxy_ajp.slo ajp_header.slo ajp_link.slo ajp_msg.slo ajp_utils.slo
	$(SH_LINK) -rpath $(libexecdir) -module -avoid-version  mod_proxy_ajp.lo ajp_header.lo ajp_link.lo ajp_msg.lo ajp_utils.lo $(MOD_PROXY_AJP_LDADD)
mod_proxy_balancer.la: mod_proxy_balancer.slo
	$(SH_LINK) -rpath $(libexecdir) -module -avoid-version  mod_proxy_balancer.lo $(MOD_PROXY_BALANCER_LDADD)
mod_proxy_express.la: mod_proxy_express.slo
	$(SH_LINK) -rpath $(libexecdir) -module -avoid-version  mod_proxy_express.lo $(MOD_PROXY_EXPRESS_LDADD)
mod_proxy_hcheck.la: mod_proxy_hcheck.slo
	$(SH_LINK) -rpath $(libexecdir) -module -avoid-version  mod_proxy_hcheck.lo $(MOD_PROXY_HCHECK_LDADD)
DISTCLEAN_TARGETS = modules.mk
static = 
shared =  mod_proxy.la mod_proxy_connect.la mod_proxy_ftp.la mod_proxy_http.la mod_proxy_fcgi.la mod_proxy_scgi.la mod_proxy_uwsgi.la mod_proxy_fdpass.la mod_proxy_wstunnel.la mod_proxy_ajp.la mod_proxy_balancer.la mod_proxy_express.la mod_proxy_hcheck.la
