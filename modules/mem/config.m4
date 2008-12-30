dnl modules enabled in this directory by default

dnl APACHE_MODULE(name, helptext[, objects[, structname[, default[, config]]]])

APACHE_MODPATH_INIT(mem)
if test "$enable_slotmem" = "shared"; then
  slotmem_mods_enable=shared
elif test "$enable_slotmem" = "yes"; then
  slotmem_mods_enable=yes
else
  slotmem_mods_enable=no
fi

slotmem_objs="mod_slotmem.lo"

APACHE_MODULE(slotmem, slot-based memory API using providers, $slotmem_objs, , most)

# Ensure that other modules can pick up mod_slotmem.h
APR_ADDTO(INCLUDES, [-I\$(top_srcdir)/$modpath_current])

APACHE_MODPATH_FINISH
