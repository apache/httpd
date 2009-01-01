dnl modules enabled in this directory by default

dnl APACHE_MODULE(name, helptext[, objects[, structname[, default[, config]]]])

APACHE_MODPATH_INIT(mem)

sharedmem_objs="mod_sharedmem.lo"
APACHE_MODULE(sharedmem, memslot provider that uses shared memory, $sharedmem_objs, , most)
APACHE_MODULE(plainmem, memslot provider that uses plain memory, , , no)

APACHE_MODPATH_FINISH
