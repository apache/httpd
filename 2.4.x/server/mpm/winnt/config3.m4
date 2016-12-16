winnt_objects="child.lo mpm_winnt.lo nt_eventlog.lo service.lo"
APACHE_MPM_MODULE(winnt, $enable_mpm_winnt, $winnt_objects)
