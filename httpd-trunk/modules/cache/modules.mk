libmod_file_cache.la: mod_file_cache.lo
	$(MOD_LINK) mod_file_cache.lo $(MOD_FILE_CACHE_LDADD)
libmod_cache.la: mod_cache.lo cache_storage.lo cache_util.lo 
	$(MOD_LINK) mod_cache.lo cache_storage.lo cache_util.lo  $(MOD_CACHE_LDADD)
libmod_cache_disk.la: mod_cache_disk.lo
	$(MOD_LINK) mod_cache_disk.lo $(MOD_CACHE_DISK_LDADD)
libmod_socache_shmcb.la: mod_socache_shmcb.lo
	$(MOD_LINK) mod_socache_shmcb.lo $(MOD_SOCACHE_SHMCB_LDADD)
libmod_socache_dbm.la: mod_socache_dbm.lo
	$(MOD_LINK) mod_socache_dbm.lo $(MOD_SOCACHE_DBM_LDADD)
libmod_socache_memcache.la: mod_socache_memcache.lo
	$(MOD_LINK) mod_socache_memcache.lo $(MOD_SOCACHE_MEMCACHE_LDADD)
DISTCLEAN_TARGETS = modules.mk
static =  libmod_file_cache.la libmod_cache.la libmod_cache_disk.la libmod_socache_shmcb.la libmod_socache_dbm.la libmod_socache_memcache.la
shared = 
