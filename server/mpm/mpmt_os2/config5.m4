APACHE_MPM_MODULE(mpmt_os2, $enable_mpm_mpmt_os2, mpmt_os2.lo mpmt_os2_child.lo,[
    APR_ADDTO(CFLAGS,-Zmt)
])
