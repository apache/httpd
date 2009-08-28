dnl modules enabled in this directory by default

dnl APACHE_MODULE(name, helptext[, objects[, structname[, default[, config]]]])

APACHE_MODPATH_INIT(mappers)

APACHE_MODULE(vhost_alias, mass virtual hosting module, , , most)
APACHE_MODULE(negotiation, content negotiation, , , yes)
APACHE_MODULE(dir, directory request handling, , , yes)
APACHE_MODULE(imagemap, server-side imagemaps, , , most)
APACHE_MODULE(actions, Action triggering on requests, , , yes)
APACHE_MODULE(speling, correct common URL misspellings, , , most)
APACHE_MODULE(userdir, mapping of requests to user-specific directories, , , yes)
APACHE_MODULE(alias, mapping of requests to different filesystem parts, , , yes)
APACHE_MODULE(rewrite, rule based URL manipulation, , , most)

APR_ADDTO(INCLUDES, [-I\$(top_srcdir)/$modpath_current])

APACHE_MODPATH_FINISH
