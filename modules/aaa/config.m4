dnl modules enabled in this directory by default

dnl APACHE_MODULE(name, helptext[, objects[, structname[, default[, config]]]])

APACHE_MODPATH_INIT(aaa)

APACHE_MODULE(access, host-based access control, , , yes)
APACHE_MODULE(auth, user-based access control, , , yes)
APACHE_MODULE(auth_anon, anonymous user access, , anon_auth, no)
APACHE_MODULE(auth_dbm, DBM-based access databases, , dbm_auth, no)

APACHE_MODULE(auth_db, DB-based access databases, , db_auth, no, [
  AC_CHECK_HEADERS(db.h)
  AC_CHECK_LIB(db,main)
]) 

APACHE_MODULE(auth_digest, digests, , digest_auth, no)

LTFLAGS="$LTFLAGS -export-dynamic"

APACHE_MODPATH_FINISH
