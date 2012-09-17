libmod_dumpio.la: mod_dumpio.lo
	$(MOD_LINK) mod_dumpio.lo $(MOD_DUMPIO_LDADD)
libmod_firehose.la: mod_firehose.lo
	$(MOD_LINK) mod_firehose.lo $(MOD_FIREHOSE_LDADD)
DISTCLEAN_TARGETS = modules.mk
static =  libmod_dumpio.la libmod_firehose.la
shared = 
