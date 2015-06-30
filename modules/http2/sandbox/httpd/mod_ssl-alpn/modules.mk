mod_ssl.la: mod_ssl.slo ssl_engine_config.slo ssl_engine_init.slo ssl_engine_io.slo ssl_engine_kernel.slo ssl_engine_log.slo ssl_engine_mutex.slo ssl_engine_pphrase.slo ssl_engine_rand.slo ssl_engine_vars.slo ssl_scache.slo ssl_util_stapling.slo ssl_util.slo ssl_util_ssl.slo ssl_engine_ocsp.slo ssl_util_ocsp.slo
	$(SH_LINK) -rpath $(libexecdir) -module -avoid-version  mod_ssl.lo ssl_engine_config.lo ssl_engine_init.lo ssl_engine_io.lo ssl_engine_kernel.lo ssl_engine_log.lo ssl_engine_mutex.lo ssl_engine_pphrase.lo ssl_engine_rand.lo ssl_engine_vars.lo ssl_scache.lo ssl_util_stapling.lo ssl_util.lo ssl_util_ssl.lo ssl_engine_ocsp.lo ssl_util_ocsp.lo  $(MOD_SSL_LDADD)
DISTCLEAN_TARGETS = modules.mk
static = 
shared =  mod_ssl.la
MOD_CFLAGS = -I/Users/sei/projects/mod-h2/httpd/gen/build/include
MOD_LDFLAGS = -L/Users/sei/projects/mod-h2/httpd/gen/build/lib -lssl -lcrypto -lpthread
