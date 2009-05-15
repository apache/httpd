dnl modules enabled in this directory by default

dnl APACHE_MODULE(name, helptext[, objects[, structname[, default[, config]]]])

APACHE_MODPATH_INIT(slotmem)

APACHE_MODULE(slotmem_shm, slotmem provider that uses shared memory, , , most)
APACHE_MODULE(slotmem_plain, slotmem provider that uses plain memory, , , no)

APACHE_MODPATH_FINISH
