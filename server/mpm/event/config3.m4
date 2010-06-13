dnl ## XXX - Need a more thorough check of the proper flags to use

APACHE_CHECK_SERF
if test "$ac_cv_serf" = yes ; then
    APR_SETVAR(MOD_MPM_EVENT_LDADD,[\$(SERF_LIBS)])
fi
APACHE_SUBST(MOD_MPM_EVENT_LDADD)

APACHE_MPM_MODULE(event, $enable_mpm_event, event.lo fdqueue.lo pod.lo,[
    AC_CHECK_FUNCS(pthread_kill)
], , [\$(MOD_MPM_EVENT_LDADD)])
