dnl modules enabled in this directory by default

dnl Session

dnl APACHE_MODULE(name, helptext[, objects[, structname[, default[, config]]]])

APACHE_MODPATH_INIT(session)

dnl Session modules; modules that are capable of storing key value pairs in
dnl various places, such as databases, LDAP, or cookies.
dnl
APACHE_MODULE(session, session module, , , most)
dnl APACHE_MODULE(session_cookie, session cookie module, , , most)
dnl APACHE_MODULE(session_crypto, session crypto module, , , most)
dnl APACHE_MODULE(session_dbd, session dbd module, , , most)
dnl APACHE_MODULE(session_ldap, session ldap module, , , most)

APACHE_MODPATH_FINISH

