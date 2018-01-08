APACHE_MPMPATH_INIT(motorz)

dnl ## XXX - Need a more thorough check of the proper flags to use

APACHE_SUBST(MOD_MPM_MOTORZ_LDADD)

APACHE_MPM_MODULE(motorz, $enable_mpm_motorz, motorz.lo,[
    AC_CHECK_FUNCS(pthread_kill)
], , [\$(MOD_MPM_MOTORZ_LDADD)])

APACHE_MPMPATH_FINISH
