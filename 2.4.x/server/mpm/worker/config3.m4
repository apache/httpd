dnl ## XXX - Need a more thorough check of the proper flags to use

APACHE_MPM_MODULE(worker, $enable_mpm_worker, worker.lo,[
    AC_CHECK_FUNCS(pthread_kill)
])
