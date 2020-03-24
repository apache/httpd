libworker.la: worker.lo
	$(MOD_LINK) worker.lo
DISTCLEAN_TARGETS = modules.mk
static = libworker.la
shared =
