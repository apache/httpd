if ap_mpm_is_enabled "prefork"; then
    APACHE_FAST_OUTPUT(server/mpm/prefork/Makefile)
fi
