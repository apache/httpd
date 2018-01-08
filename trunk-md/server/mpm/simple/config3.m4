APACHE_MPMPATH_INIT(simple)

simple_objects="simple_api.lo simple_children.lo simple_core.lo \
simple_event.lo simple_run.lo simple_io.lo"
APACHE_MPM_MODULE(simple, $enable_mpm_simple, $simple_objects)

APACHE_MPMPATH_FINISH
