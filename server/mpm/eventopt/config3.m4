dnl ## XXX - Need a more thorough check of the proper flags to use

APACHE_CHECK_SERF
if test "$ac_cv_serf" = yes ; then
    APR_ADDTO(MOD_MPM_EVENTOPT_LDADD,[\$(SERF_LIBS)])
fi
APACHE_SUBST(MOD_MPM_EVENTOPT_LDADD)

APACHE_MPM_MODULE(eventopt, $enable_mpm_eventopt, eventopt.lo fdqueue.lo equeue.lo pod.lo,[
    AC_CHECK_FUNCS(pthread_kill)
], , [\$(MOD_MPM_EVENTOPT_LDADD)])
