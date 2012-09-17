libmod_dav_fs.la: mod_dav_fs.lo dbm.lo lock.lo repos.lo
	$(MOD_LINK) mod_dav_fs.lo dbm.lo lock.lo repos.lo $(MOD_DAV_FS_LDADD)
DISTCLEAN_TARGETS = modules.mk
static =  libmod_dav_fs.la
shared = 
