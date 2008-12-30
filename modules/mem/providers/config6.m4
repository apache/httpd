dnl modules enabled in this directory by default

dnl APACHE_MODULE(name, helptext[, objects[, structname[, default[, config]]]])

APACHE_MODPATH_INIT(mem/providers)

sharedmem_objs="mod_sharedmem.lo"
APACHE_MODULE(sharedmem, memslot provider that uses shared memory, $sharedmem_objs, , $slotmem_mods_enable)
APACHE_MODULE(plainmem, memslot provider that uses plain memory, , , no)

# Ensure that other modules can pick up slotmem.h
APR_ADDTO(INCLUDES, [-I\$(top_srcdir)/$modpath_current])

APACHE_MODPATH_FINISH
