dnl ## XXX - Need a more thorough check of the proper flags to use

if test "$MPM_NAME" = "perchild" ; then

    APACHE_FAST_OUTPUT(server/mpm/$MPM_SUBDIR_NAME/Makefile)
fi
