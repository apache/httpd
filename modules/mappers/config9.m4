dnl modules enabled in this directory by default

dnl APACHE_MODULE(name, helptext[, objects[, structname[, default[, config]]]])

APACHE_MODPATH_INIT(mappers)

APACHE_MODULE(vhost_alias, mass hosting module, , , most)
APACHE_MODULE(negotiation, content negoatiation, , , yes)
APACHE_MODULE(dir, directory request handling, , , yes)
APACHE_MODULE(imap, internal imagemaps, , , yes)
APACHE_MODULE(actions, Action triggering on requests, , , yes)
APACHE_MODULE(speling, correct common URL misspellings, , , most)
APACHE_MODULE(userdir, mapping of user requests, , , yes)
APACHE_MODULE(alias, translation of requests, , , yes)

APACHE_MODULE(rewrite, regex URL translation, , , most, [
  APR_ADDTO(CFLAGS,-DNO_DBM_REWRITEMAP)
])

ap_old_cppflags=$CPPFLAGS
CPPFLAGS="$CPPFLAGS -I$APR_SOURCE_DIR/include"
AC_TRY_COMPILE([#include <apr.h>], 
[#if !APR_HAS_DSO
#error You need APR DSO support to use mod_so. 
#endif],ap_enable_so="static",ap_enable_so="no")
CPPFLAGS=$ap_old_cppflags

APACHE_MODULE(so, DSO capability, , , $ap_enable_so)

dnl ### why save the cache?
AC_CACHE_SAVE

APACHE_MODPATH_FINISH
