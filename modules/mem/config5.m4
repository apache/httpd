dnl modules enabled in this directory by default

dnl APACHE_MODULE(name, helptext[, objects[, structname[, default[, config]]]])

APACHE_MODPATH_INIT(mem)

APACHE_MODULE(scoreboard, memslot provider that uses scoreboard, , , no)
APACHE_MODULE(sharedmem, memslot provider that shared memory, , , no)
APACHE_MODULE(plainmem, memslot provider that plain memory, , , no)

# Ensure that other modules can pick up slotmem.h
APR_ADDTO(INCLUDES, [-I\$(top_srcdir)/$modpath_current])

APACHE_MODPATH_FINISH
