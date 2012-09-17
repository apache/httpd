libmod_slotmem_shm.la: mod_slotmem_shm.lo
	$(MOD_LINK) mod_slotmem_shm.lo $(MOD_SLOTMEM_SHM_LDADD)
DISTCLEAN_TARGETS = modules.mk
static =  libmod_slotmem_shm.la
shared = 
