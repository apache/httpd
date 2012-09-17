libevent.la: event.lo fdqueue.lo pod.lo
	$(MOD_LINK) event.lo fdqueue.lo pod.lo
DISTCLEAN_TARGETS = modules.mk
static = libevent.la
shared =
