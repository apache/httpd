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

dnl ### this isn't going to work quite right because of ordering issues
dnl ### among the config.m4 files. it is possible that a *later* module
dnl ### is marked as shared (thus setting sharedobjs), so we won't see
dnl ### it here. we need to shift *this* config.m4 to be "last" or we
dnl ### need to find a different way to set up this default and module spec.
if test "$sharedobjs" = "yes"; then
    APACHE_MODULE(so, DSO capability, , , yes)
else
    APACHE_MODULE(so, DSO capability, , , no)
fi
dnl ### why save the cache?
AC_CACHE_SAVE

APACHE_MODPATH_FINISH
