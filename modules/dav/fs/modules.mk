mod_dav_fs.la: mod_dav_fs.slo dbm.slo lock.slo repos.slo
	$(SH_LINK) -rpath $(libexecdir) -module -avoid-version  mod_dav_fs.lo dbm.lo lock.lo repos.lo $(MOD_DAV_FS_LDADD)
DISTCLEAN_TARGETS = modules.mk
static = 
shared =  mod_dav_fs.la
