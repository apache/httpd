mod_tls.la: mod_tls.slo tls_cache.slo tls_cert.slo tls_conf.slo tls_core.slo tls_filter.slo tls_ocsp.slo tls_proto.slo tls_util.slo tls_var.slo
	$(SH_LINK) -rpath $(libexecdir) -module -avoid-version  mod_tls.lo tls_cache.lo tls_cert.lo tls_conf.lo tls_core.lo tls_filter.lo tls_ocsp.lo tls_proto.lo tls_util.lo tls_var.lo  $(MOD_TLS_LDADD)
DISTCLEAN_TARGETS = modules.mk
static = 
shared =  mod_tls.la
MOD_CFLAGS = -I/opt/apache-trunk/include
MOD_LDFLAGS = -L/opt/apache-trunk/lib
