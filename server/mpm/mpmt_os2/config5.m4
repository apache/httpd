if ap_mpm_is_enabled "mpmt_os2"; then
    AC_CACHE_SAVE
    APACHE_FAST_OUTPUT(server/mpm/mpmt_os2/Makefile)
    APR_ADDTO(CFLAGS,-Zmt)
fi
