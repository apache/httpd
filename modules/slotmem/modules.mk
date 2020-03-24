mod_slotmem_shm.la: mod_slotmem_shm.slo
	$(SH_LINK) -rpath $(libexecdir) -module -avoid-version  mod_slotmem_shm.lo $(MOD_SLOTMEM_SHM_LDADD)
DISTCLEAN_TARGETS = modules.mk
static = 
shared =  mod_slotmem_shm.la
