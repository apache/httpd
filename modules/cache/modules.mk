mod_file_cache.la: mod_file_cache.slo
	$(SH_LINK) -rpath $(libexecdir) -module -avoid-version  mod_file_cache.lo $(MOD_FILE_CACHE_LDADD)
mod_cache.la: mod_cache.slo cache_storage.slo cache_util.slo
	$(SH_LINK) -rpath $(libexecdir) -module -avoid-version  mod_cache.lo cache_storage.lo cache_util.lo  $(MOD_CACHE_LDADD)
mod_cache_disk.la: mod_cache_disk.slo
	$(SH_LINK) -rpath $(libexecdir) -module -avoid-version  mod_cache_disk.lo $(MOD_CACHE_DISK_LDADD)
mod_cache_socache.la: mod_cache_socache.slo
	$(SH_LINK) -rpath $(libexecdir) -module -avoid-version  mod_cache_socache.lo $(MOD_CACHE_SOCACHE_LDADD)
mod_socache_shmcb.la: mod_socache_shmcb.slo
	$(SH_LINK) -rpath $(libexecdir) -module -avoid-version  mod_socache_shmcb.lo $(MOD_SOCACHE_SHMCB_LDADD)
mod_socache_dbm.la: mod_socache_dbm.slo
	$(SH_LINK) -rpath $(libexecdir) -module -avoid-version  mod_socache_dbm.lo $(MOD_SOCACHE_DBM_LDADD)
mod_socache_memcache.la: mod_socache_memcache.slo
	$(SH_LINK) -rpath $(libexecdir) -module -avoid-version  mod_socache_memcache.lo $(MOD_SOCACHE_MEMCACHE_LDADD)
mod_socache_redis.la: mod_socache_redis.slo
	$(SH_LINK) -rpath $(libexecdir) -module -avoid-version  mod_socache_redis.lo $(MOD_SOCACHE_REDIS_LDADD)
DISTCLEAN_TARGETS = modules.mk
static = 
shared =  mod_file_cache.la mod_cache.la mod_cache_disk.la mod_cache_socache.la mod_socache_shmcb.la mod_socache_dbm.la mod_socache_memcache.la mod_socache_redis.la
