if test "$MPM_NAME" = "prefork" ; then
    APACHE_OUTPUT(modules/mpm/$MPM_NAME/Makefile)

    APACHE_MPM_CHECK_SHMEM
fi
