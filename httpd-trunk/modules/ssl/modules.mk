libmod_ssl.la: mod_ssl.lo ssl_engine_config.lo ssl_engine_dh.lo ssl_engine_init.lo ssl_engine_io.lo ssl_engine_kernel.lo ssl_engine_log.lo ssl_engine_mutex.lo ssl_engine_pphrase.lo ssl_engine_rand.lo ssl_engine_vars.lo ssl_scache.lo ssl_util_stapling.lo ssl_util.lo ssl_util_ssl.lo ssl_engine_ocsp.lo ssl_util_ocsp.lo 
	$(MOD_LINK) mod_ssl.lo ssl_engine_config.lo ssl_engine_dh.lo ssl_engine_init.lo ssl_engine_io.lo ssl_engine_kernel.lo ssl_engine_log.lo ssl_engine_mutex.lo ssl_engine_pphrase.lo ssl_engine_rand.lo ssl_engine_vars.lo ssl_scache.lo ssl_util_stapling.lo ssl_util.lo ssl_util_ssl.lo ssl_engine_ocsp.lo ssl_util_ocsp.lo  $(MOD_SSL_LDADD)
DISTCLEAN_TARGETS = modules.mk
static =  libmod_ssl.la
shared = 
MOD_CFLAGS = -I/opt/local/include  
MOD_LDFLAGS = -L/opt/local/lib   -lssl -lcrypto -lpthread
