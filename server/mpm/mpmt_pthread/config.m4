dnl ## XXX - Need a more thorough check of the proper flags to use

if test "$MPM_NAME" = "mpmt_pthread" ; then
    APACHE_OUTPUT(modules/mpm/$MPM_NAME/Makefile)
    APACHE_MPM_PTHREAD
    APACHE_MPM_CHECK_SHMEM
fi
